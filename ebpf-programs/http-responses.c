#include <linux/skbuff.h>
#include <net/sock.h>

struct http_response_codes_t {
    u64 codes[8];
};

/* Hash map from (Task group id|Task id) to (Number of sent http responses' codes).
   We need to gather requests per task and not only per task group (i.e. userspace pid)
   so that entries can be cleared up independently when a task exists.
   This implies that userspace needs to do the per-process aggregation.
 */
BPF_HASH(sent_http_responses, u64, struct http_response_codes_t);

/* skb_copy_datagram_iter() (Kernels >= 3.19) is in charge of copying socket
   buffers from kernel to userspace.

   skb_copy_datagram_iter() has an associated tracepoint
   (trace_skb_copy_datagram_iovec), which would be more stable than a kprobe but
   it lacks the offset argument.
 */
int kprobe__skb_copy_datagram_iter(struct pt_regs *ctx, const struct sk_buff *skb, int offset, void *unused_iovec, int len)
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
  /* The minimum length of http response is always greater than 12 bytes
     HTTP/1.1 XXX message
     What about HTTP/2?
  */
  unsigned int available_data = head_len - offset;
  if (available_data < 12) {
    return 0;
  }

  /* Check if buffer begins with the string "HTTP/1.1 ".

     To avoid false positives it would be good to do a deeper inspection
     (i.e. fully ensure a 'ProtocolVersion SP ThreeDigitCode SP Message CRLF'
     structure) but loops are not allowed in ebpf, making variable-size-data
     parsers infeasible.
  */
  /*
    TODO alepuccetti: The code description?
  */
  u8 data[12] = {};
  bpf_probe_read(&data, 12, skb->data + offset);

  /*
    TODO alepuccetti: support other HTTP versions
  */
  switch (data[0]) {
    /* "HTTP/1.1 " */
    case 'H':
      if ((data[1] != 'T') || (data[2] != 'T') || (data[3] != 'P') ||
          (data[4] != '/') || (data[5] != '1') || (data[6] != '.') || (data[7] != '1') ||
          (data[8] != ' ')) {
        return 0;
      }
      break;
    default:
      return 0;
  }

  u8 hundreds = (u8)data[9];
  u8 tens = (u8)data[10];
  u8 units = (u8)data[11];

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

  u64 pid_tgid = bpf_get_current_pid_tgid();
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
        return 0;
  }

  return 0;
}


/* Clear out request count entries of tasks on exit */
int kprobe__do_exit(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  sent_http_responses.delete(&pid_tgid);
  return 0;
}
