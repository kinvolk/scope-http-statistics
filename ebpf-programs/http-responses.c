#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/inet_sock.h>

struct http_response_codes_t {
    u64 codes[8];
};

/* Hash map from (Task group id|Task id) to (Number of sent http responses' codes).
   We need to gather responses per task and not only per task group (i.e. userspace pid)
   so that entries can be cleared up independently when a task exists.
   This implies that userspace needs to do the per-process aggregation.
 */
BPF_HASH(sent_http_responses, u64, struct http_response_codes_t);
BPF_HASH(curr_data, u64, unsigned char*);
BPF_HASH(curr_skb, u64, const struct sk_buff*);
BPF_HASH(curr_offset, u64, int);

int kprobe__skb_copy_datagram_from_iter(struct pt_regs *ctx, const struct sk_buff *skb, int offset, struct iov_iter *iovec, int len)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  const struct sk_buff *skbp = NULL;
  bpf_probe_read(&skbp, sizeof(const struct sk_buff *), &skb);

  curr_skb.update(&pid_tgid, &skb);
  curr_offset.update(&pid_tgid, &offset);

  unsigned char *data_ptr = NULL;
  bpf_probe_read(&data_ptr, sizeof(data_ptr), &skbp->data);
  curr_data.update(&pid_tgid, &data_ptr);

  return 0;
}

/* skb_copy_datagram_iter() (Kernels >= 3.19) is in charge of copying socket
   buffers from kernel to userspace.

   skb_copy_datagram_iter() has an associated tracepoint
   (trace_skb_copy_datagram_iovec), which would be more stable than a kprobe but
   it lacks the offset argument.
 */

int kretprobe__skb_copy_datagram_from_iter(struct pt_regs *ctx)
{

  /* Inspect the beginning of socket buffers copied to user-space to determine
     if they correspond to http responses.

     Caveats:

     Requests may not appear at the beginning of a packet due to:
     * Persistent connections.
     * Packet fragmentation.

     We could inspect the full packet but:
     * It's very inefficient.
     * Examining the non-linear (paginated) area of a socket buffer would be
       really tricky from ebpf.
  */

  int ret = PT_REGS_RC(ctx);
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct sk_buff **skbpp = 0;
  skbpp = (struct sk_buff **)curr_skb.lookup(&pid_tgid);
  int offset = -1;
  int *offsetp = 0;
  offsetp = (int *)curr_offset.lookup(&pid_tgid);
  bpf_probe_read(&offset, sizeof(int), offsetp);

  if (skbpp == 0) {
    goto cleanup;   // missed entry
  }

  if (ret != 0) {
    goto cleanup;
  }

  struct sk_buff *skbp = NULL;
  bpf_probe_read(&skbp, sizeof(const struct sk_buff *), skbpp);

  if (skbp == 0) {
    goto cleanup;
   }

  /*
    copy into the stack the parts of skb that we want
  */
  struct sock *skp = 0;
  bpf_probe_read(&skp, sizeof(struct sock *), &skbp->sk);

  unsigned short skc_family = 0;
  unsigned int skb_len = 0;
  unsigned int skb_data_len = 0;
  unsigned char data[12] = {0,};

  bpf_probe_read(&skc_family, sizeof(unsigned short), &skp->__sk_common.skc_family);
  bpf_probe_read(&skb_len, sizeof(unsigned int), &skbp->len);
  bpf_probe_read(&skb_data_len, sizeof(unsigned int), &skbp->data_len);

  /* Verify it's a TCP socket
     TODO: is it worth caching it in a socket table?
     Ensure we are tracking a unix socket
  */
  switch (skc_family) {
    case PF_UNIX:
      break;
    default:
      goto cleanup;
  }

  /* The socket type and protocol are not directly addressable since they are
     bitfields.  We access them by assuming sk_write_queue is immediately before
     them (admittedly pretty hacky).
  */
  unsigned int flags = 0;
  size_t flags_offset = offsetof(typeof(struct sock), sk_write_queue) + sizeof(skp->sk_write_queue);
  bpf_probe_read(&flags, sizeof(flags), ((u8*)skp) + flags_offset);
  u16 sk_type = flags >> 16;
  if (sk_type != SOCK_STREAM) {
    goto cleanup;
  }
  u8 sk_protocol = flags >> 8 & 0xFF;
  /* The protocol is unset (IPPROTO_IP) in Unix sockets */
  if ( (sk_protocol != IPPROTO_TCP) && ((skc_family == PF_UNIX) && (sk_protocol != IPPROTO_IP)) ) {
    goto cleanup;
  }

  /* Inline implementation of skb_headlen() */
  unsigned int head_len = skb_len - skb_data_len;
  /* The minimum length of http response is always greater than 12 bytes
     HTTP/1.1 XXX message
     What about HTTP/2?
  */
  unsigned int available_data = head_len - offset;
  if (available_data < 12) {
    goto cleanup;
  }
  unsigned char **data_pp = NULL;
  unsigned char *data_ptr = NULL;

  data_pp = (unsigned char**)curr_data.lookup(&pid_tgid);
  if (data_pp == NULL) {
    goto cleanup;
  }

  bpf_probe_read(&data_ptr, sizeof(void *), data_pp);
  if (data_ptr != NULL) {
    bpf_probe_read(&data, 12, data_ptr);
  } else {
    bpf_trace_printk("data_ptr = NULL...\n");
    goto cleanup;
  }

  /* Check if buffer begins with the string "HTTP/1.1 ".
     To avoid false positives it would be good to do a deeper inspection
     (i.e. fully ensure a 'ProtocolVersion SP ThreeDigitCode SP Message CRLF'
     structure) but loops are not allowed in ebpf, making variable-size-data
     parsers infeasible.
    TODO alepuccetti: support other HTTP versions
  */
  switch (data[0]) {
    /* "HTTP/1.1 " */
    case 'H':
      if ((data[1] != 'T') || (data[2] != 'T') || (data[3] != 'P') ||
          (data[4] != '/') || (data[5] != '1') || (data[6] != '.') || (data[7] != '1') ||
          (data[8] != ' ')) {
        goto cleanup;
      }
      bpf_trace_printk("kretprobe: HTTP/1.1 FOUND!!!\n");
      bpf_trace_printk("data: %s\n", data);
      break;
    default:
      goto cleanup;
  }

  char hundreds = data[9];
  char tens = data[10];
  char units = data[11];

  if (hundreds < '0' || hundreds > '9') {
        goto cleanup;
  } else {
       hundreds -= '0';
  }
  if (tens < '0' || tens > '9') {
        goto cleanup;
  } else {
       tens -= '0';
  }
   if (units < '0' || units > '9') {
        goto cleanup;
  } else {
       units -= '0';
  }

  u16 http_code = hundreds * 100 + tens * 10 + units;

  struct http_response_codes_t new_codes_counts;
  memset(new_codes_counts.codes, 0, 8 * sizeof(u64));

  struct http_response_codes_t* current_codes_counts = sent_http_responses.lookup_or_init(&pid_tgid, &new_codes_counts);
  new_codes_counts = *current_codes_counts;

  switch (http_code) {
    case 200:
        new_codes_counts.codes[2]++;
        sent_http_responses.update(&pid_tgid, &new_codes_counts);
        break;
    case 404:
        new_codes_counts.codes[4]++;
        sent_http_responses.update(&pid_tgid, &new_codes_counts);
        break;
    default:
        goto cleanup;
  }

cleanup:
    curr_data.delete(&pid_tgid);
    curr_skb.delete(&pid_tgid);
    curr_offset.delete(&pid_tgid);
    return 0;
}


/* Clear out request count entries of tasks on exit */
int kprobe__do_exit(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  sent_http_responses.delete(&pid_tgid);
  return 0;
}
