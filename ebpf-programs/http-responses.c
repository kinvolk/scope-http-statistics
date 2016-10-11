#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/inet_sock.h>

struct http_response_codes_t {
    u64 codes[8];
};

struct sk_buff_off_t {
 const struct sk_buff *skb;
 int offset;
};

/* Hash map from (Task group id|Task id) to (Number of sent http responses' codes).
   We need to gather requests per task and not only per task group (i.e. userspace pid)
   so that entries can be cleared up independently when a task exists.
   This implies that userspace needs to do the per-process aggregation.
 */
BPF_HASH(sent_http_responses, u64, struct http_response_codes_t);
BPF_HASH(currdata, u64, unsigned char*);
BPF_HASH(currskb, u64, const struct sk_buff*);
BPF_HASH(curroff, u64, int);

int kprobe__skb_copy_datagram_iter(struct pt_regs *ctx, const struct sk_buff *skb, int offset, void *unused_iovec, int len)
{
  /* Inspect the beginning of socket buffers copied to user-space to determine
     if they correspond to http requests.

     Caveats:

     Requests may not appear at the beginning of a packet due to:
     * Persistent connections.
     * Packet fragmentation.

     We could inspect the full packet but:
     * It's very inefficient.
     * Examining the non-linear (paginated) area of a socket buffer would be
       really tricky from ebpf.
  */

  /* Verify it's a TCP socket
     TODO: is it worth caching it in a socket table?
   */
  struct sock *sk = skb->sk;
  unsigned short skc_family = sk->__sk_common.skc_family;
  switch (skc_family) {
    case PF_INET:
    case PF_INET6:
    case PF_UNIX:
      break;
    default:
      return 0;
  }
  /* The socket type and protocol are not directly addressable since they are
     bitfields.  We access them by assuming sk_write_queue is immediately before
     them (admittedly pretty hacky).
  */
  unsigned int flags = 0;
  size_t flags_offset = offsetof(typeof(struct sock), sk_write_queue) + sizeof(sk->sk_write_queue);
  bpf_probe_read(&flags, sizeof(flags), ((u8*)sk) + flags_offset);
  u16 sk_type = flags >> 16;
  if (sk_type != SOCK_STREAM) {
    return 0;
  }
  u8 sk_protocol = flags >> 8 & 0xFF;
  /* The protocol is unset (IPPROTO_IP) in Unix sockets */
  if ( (sk_protocol != IPPROTO_TCP) && ((skc_family == PF_UNIX) && (sk_protocol != IPPROTO_IP)) ) {
    return 0;
  }

  /* Inline implementation of skb_headlen() */
  unsigned int head_len = skb->len - skb->data_len;
  /* http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
     minimum length of http request is always greater than 7 bytes
  */
  //unsigned int available_data = head_len - offset;
  //if (available_data < 12) {
  //  return 0;
 // }
//  bpf_trace_printk("skb_len: %u, skb_data_len: %u\n", skb->len, skb->data_len);
  /* Check if buffer begins with a method name followed by a space.

     To avoid false positives it would be good to do a deeper inspection
     (i.e. fully ensure a 'Method SP Request-URI SP HTTP-Version CRLF'
     structure) but loops are not allowed in ebpf, making variable-size-data
     parsers infeasible.
  */
  u8 data[12] = {0,};
  bpf_probe_read(&data, 12, skb->data + offset);
//  bpf_trace_printk("data: %s\n", data);

  switch (data[0]) {
    /* "HTTP/1.1 " */
    case 'H':
      if ((data[1] != 'T') || (data[2] != 'T') || (data[3] != 'P') ||
          (data[4] != '/') || (data[5] != '1') || (data[6] != '.') || (data[7] != '1') ||
          (data[8] != ' ')) {
//        bpf_trace_printk("[H]TTP/1.1 not found\n");
        return 0;
      }
      bpf_trace_printk("_iter: kprobe ----- skb: %p, offset: %d\n", skb, offset);
      bpf_trace_printk("_iter: kprobe: HTTP/1.1 FOUND!!!\n");
      bpf_trace_printk("kprobe data: %d %d\n", data[0], data[1]);
      bpf_trace_printk("kprobe data: %d %d\n", data[2], data[3]);
      break;
    default:
//      bpf_trace_printk("HTTP/1.1 not found\n");
      return 0;
  }

//  bpf_trace_printk("available_data: %u\n", available_data);
//  bpf_trace_printk("data: %s\n", &data);

  char hundreds = data[9];
  char tens = data[10];
  char units = data[11];

  if (hundreds < '0' || hundreds > '9') {
        return 0;
  } else {
       hundreds -= '0';
  }
  if (tens < '0' || tens > '9') {
        return 0;
  } else {
       tens -= '0';
  }
   if (units < '0' || units > '9') {
        return 0;
  } else {
       units -= '0';
  }

  u16 http_code = hundreds * 100 + tens * 10 + units;
  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct http_response_codes_t new_codes_counts;
  memset(new_codes_counts.codes, 0, 8 * sizeof(u64));

  struct http_response_codes_t* current_codes_counts = sent_http_responses.lookup_or_init(&pid_tgid, &new_codes_counts);
  new_codes_counts = *current_codes_counts;
  // TODO alepuccetti: should current_codes_counts be freed?

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
        return 0;
  }

  return 0;
}

int kprobe__skb_copy_datagram_from_iter(struct pt_regs *ctx, const struct sk_buff *skb, int offset, struct iov_iter *iovec, int len)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  // stash the sock buffer ptr for lookup on return
//  struct sk_buff_off_t skboff;
//  struct sk_buff_off_t* skboffp;
//  skboffp = &skboff;
//  memset(&skboffp->skb, 0, sizeof(const struct sk_buff*));
//  memset(&skboffp->offset, 0, sizeof(int));
//  skboff.skb = skb;
//  bpf_probe_read(&skboffp->skb, sizeof(const struct sk_buff *), &skb);
//  skboff.offset = offset;
//  bpf_probe_read(&skboffp->offset, sizeof(int), &offset);
//  currskoff.update(&pid_tgid, &skboff);
//  currskoff.update(&pid_tgid, &skboffp);

//  bpf_trace_printk("--------- offset: %u\n", offset);
  const struct sk_buff *skbp = NULL;
  bpf_probe_read(&skbp, sizeof(const struct sk_buff *), &skb);
  //bpf_trace_printk("_from_iter: kprobe [%u] ----- skbp: %p, skb: %p\n", pid_tgid, skbp, skb);
  //bpf_trace_printk("_from_iter: kprobe [%u] ----- offset: %d\n", pid_tgid, offset);
//  bpf_trace_printk("kprobe [%u] ----- skb->data: %p\n", pid_tgid, skb->data);

  currskb.update(&pid_tgid, &skb);
  curroff.update(&pid_tgid, &offset);

  bpf_trace_printk("kprobe from_iter: skb=%p len=%d\n", skb, len);

  unsigned char *data_ptr = NULL;
  unsigned char *head_ptr = NULL;
  bpf_probe_read(&data_ptr, sizeof(data_ptr), &skbp->data);
  bpf_probe_read(&head_ptr, sizeof(head_ptr), &skbp->head);
  currdata.update(&pid_tgid, &data_ptr);

  bpf_trace_printk("kprobe data_ptr=%p head_ptr=%p diff=%p\n", data_ptr, head_ptr, data_ptr - head_ptr);

  return 0;
}

/* skb_copy_datagram_iter() (Kernels >= 3.19) is in charge of copying socket
   buffers from kernel to userspace.

   skb_copy_datagram_iter() has an associated tracepoint
   (trace_skb_copy_datagram_iovec), which would be more stable than a kprobe but
   it lacks the offset argument.
 */
//int kprobe__skb_copy_datagram_iter(struct pt_regs *ctx, const struct sk_buff *skb, int offset, void *unused_iovec, int len)
//int kprobe__skb_copy_datagram_from_iter(struct pt_regs *ctx, const struct sk_buff *skb, int offset, struct iov_iter *from, int len)
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
  skbpp = (struct sk_buff **)currskb.lookup(&pid_tgid);
  int offset = -1;
  int *offsetp = 0;
  offsetp = (int *)curroff.lookup(&pid_tgid);
  bpf_probe_read(&offset, sizeof(int), offsetp);

  if (skbpp == 0) {
    return 0;   // missed entry
  }

  if (ret != 0) {
//    goto cleanup;
    return 0;
  }

  struct sk_buff *skbp = NULL;
  bpf_probe_read(&skbp, sizeof(const struct sk_buff *), skbpp);

  if (skbp == 0) {
//    goto cleanup;
    return 0;
   }

  /*
    copy into the stack the parts of skb that we want
  */
//  const struct sock *skp;
  struct sock *skp = 0;
  bpf_probe_read(&skp, sizeof(struct sock *), &skbp->sk);
//  skp = skbp->sk;

  unsigned short skc_family = 0;
  unsigned int skb_len = 0;
  unsigned int skb_data_len = 0;
  unsigned char data[12] = {0,};

  bpf_probe_read(&skc_family, sizeof(unsigned short), &skp->__sk_common.skc_family);
//  skc_family = skp->__sk_common.skc_family;
  bpf_probe_read(&skb_len, sizeof(unsigned int), &skbp->len);
//  skb_len = skbp->len;
  bpf_probe_read(&skb_data_len, sizeof(unsigned int), &skbp->data_len);
//  skb_data_len = skbp->data_len;

  bpf_trace_printk("_from_iter: kretprobe [%u] ----- skbp: %p, skbpp: %p\n", pid_tgid, skbp, skbpp);
  bpf_trace_printk("_from_iter: kretprobe [%u] ----- offset: %d data_len=%d\n", pid_tgid, offset, skb_data_len);

  //if (skb_data_len != 0) {
//      bpf_trace_printk("skb_len: %u, skb_data_len: %u\nI", skb_len, skb_data_len);
  //}

  //if (skb_data_len < 12) {
//    goto cleanup;
    //return 0;
  //}
  /* Verify it's a TCP socket
     TODO: is it worth caching it in a socket table?
  */
  switch (skc_family) {
    case PF_INET:
    case PF_INET6:
    case PF_UNIX:
      break;
    default:
//      goto cleanup;
      return 0;
  }
//  bpf_trace_printk("skc_family == PF_INET | PF_INET6 | PF_UNIX\n");

//  bpf_probe_read(&data, 12, skbp->data + offset);
//  bpf_trace_printk("data: %s\n", data);
//  return 0;
  /* The socket type and protocol are not directly addressable since they are
     bitfields.  We access them by assuming sk_write_queue is immediately before
     them (admittedly pretty hacky).
  */
  unsigned int flags = 0;
  size_t flags_offset = offsetof(typeof(struct sock), sk_write_queue) + sizeof(skp->sk_write_queue);
  bpf_probe_read(&flags, sizeof(flags), ((u8*)skp) + flags_offset);
  u16 sk_type = flags >> 16;
  if (sk_type != SOCK_STREAM) {
//    goto cleanup;
    return 0;
  }
//  bpf_trace_printk("sk_type == SOCK_STREAM\n");
  u8 sk_protocol = flags >> 8 & 0xFF;
  /* The protocol is unset (IPPROTO_IP) in Unix sockets */
  if ( (sk_protocol != IPPROTO_TCP) && ((skc_family == PF_UNIX) && (sk_protocol != IPPROTO_IP)) ) {
//    goto cleanup;
    return 0;
  }

  /* Inline implementation of skb_headlen() */
  unsigned int head_len = skb_len - skb_data_len;
  /* The minimum length of http response is always greater than 12 bytes
     HTTP/1.1 XXX message
     What about HTTP/2?
  */

  unsigned int available_data = head_len - offset;
  bpf_trace_printk("head_len: %u, offset: %u, available_data: %u\n", head_len, offset, available_data);
  //bpf_trace_printk("_from_iter: kretprobe avail: %u\n", available_data);
  //if (available_data < 12) {
//    goto cleanup;
  //  return 0;
  //}
  //bpf_trace_printk("available_data > 12: head=%p data=%p\n", skbp->head, skbp->data);

//  bpf_probe_read(&data, 12, skbp->data + offset);
  unsigned char **data_pp = NULL;
  unsigned char *data_ptr = NULL;
  unsigned char *head_ptr = NULL;

  data_pp = (unsigned char**)currdata.lookup(&pid_tgid);
  if (data_pp == NULL) {
    return 0;
  }

  bpf_probe_read(&data_ptr, sizeof(void *), data_pp);
  bpf_probe_read(&head_ptr, sizeof(head_ptr), &skbp->head);
  bpf_trace_printk("kretprobe data_ptr=%p head_ptr=%p diff=%p\n", data_ptr, head_ptr, data_ptr - head_ptr);
  if (data_ptr != NULL) {
    bpf_probe_read(&data, 12, data_ptr);
  } else {
    bpf_trace_printk("data_ptr = NULL...\n");
  }
//  bpf_trace_printk("data: %s\n", data);
//  bpf_trace_printk("kprobe [%u] ----- skbp->data: %p, &skbp->data: %p\n", pid_tgid, skbp->data, &skbp->data);

  /* Check if buffer begins with the string "HTTP/1.1 ".

     To avoid false positives it would be good to do a deeper inspection
     (i.e. fully ensure a 'ProtocolVersion SP ThreeDigitCode SP Message CRLF'
     structure) but loops are not allowed in ebpf, making variable-size-data
     parsers infeasible.
  */
  /*
    TODO alepuccetti: The code description?
  */
//  u8 data[12] = {0,};
//  u8 data[32] = {0,};
//  bpf_probe_read(&data, 32, skbp->data + offset);

  /*
    TODO alepuccetti: support other HTTP versions
  */
//  bpf_trace_printk("data: %s\n", data);
    int i = 0;
//  for (i = 0; i < 8; i++) {
//    bpf_trace_printk("data[%d]: %c\n", i, data[i]);
//  }
    //bpf_trace_printk("kretprobe data: %s\n", &data);
    bpf_trace_printk("kretprobe data: %d %d\n", data[0], data[1]);
    bpf_trace_printk("kretprobe data: %d %d\n", data[2], data[3]);

    //bpf_trace_printk("kretprobe data[%d]: %d\n", i, data[i]);i++;

  switch (data[0]) {
    /* "HTTP/1.1 " */
    case 'H':
      if ((data[1] != 'T') || (data[2] != 'T') || (data[3] != 'P') ||
          (data[4] != '/') || (data[5] != '1') || (data[6] != '.') || (data[7] != '1') ||
          (data[8] != ' ')) {
//        bpf_trace_printk("[H]TTP/1.1 not found\n");
        return 0;
      }
      bpf_trace_printk("kretprobe: HTTP/1.1 FOUND!!!\n");
      break;
    default:
//      bpf_trace_printk("HTTP/1.1 not found\n");
      return 0;
  }
//  bpf_trace_printk("available_data: %u\n", available_data);
//  bpf_trace_printk("data: %s\n", &data);

  char hundreds = data[9];
  char tens = data[10];
  char units = data[11];

  if (hundreds < '0' || hundreds > '9') {
        return 0;
  } else {
       hundreds -= '0';
  }
  if (tens < '0' || tens > '9') {
        return 0;
  } else {
       tens -= '0';
  }
   if (units < '0' || units > '9') {
        return 0;
  } else {
       units -= '0';
  }

  u16 http_code = hundreds * 100 + tens * 10 + units;

  struct http_response_codes_t new_codes_counts;
  memset(new_codes_counts.codes, 0, 8 * sizeof(u64));

  struct http_response_codes_t* current_codes_counts = sent_http_responses.lookup_or_init(&pid_tgid, &new_codes_counts);
  new_codes_counts = *current_codes_counts;
  // TODO alepuccetti: should current_codes_counts be freed?

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
        return 0;
  }

  return 0;

cleanup:
    currdata.delete(&pid_tgid);
    currskb.delete(&pid_tgid);
    curroff.delete(&pid_tgid);
    return 0;
}


/* Clear out request count entries of tasks on exit */
int kprobe__do_exit(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  sent_http_responses.delete(&pid_tgid);
  return 0;
}
