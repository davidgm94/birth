const MessageQueue = @This();

const common = @import("common");
const assert = common.assert;

const RNU = @import("RNU");
const Message = RNU.Message;

const max_length = 512;
enlisted: u32 = 0,
completed: u32 = 0,
next_read: u32 = 0,
next_write: u32 = 0,
messages: [max_length]Message = undefined,

pub fn send(message_queue: *volatile MessageQueue, message: Message) !void {
    // TODO: lock
    // TODO: merge messages
    const next = (message_queue.next_write + 1) % @intCast(u32, message_queue.messages.len);
    assert(next != message_queue.next_read);
    const message_ptr = &message_queue.messages[message_queue.next_write];
    message_ptr.* = message;
    message_queue.enlisted += 1;
    @fence(.SeqCst);
    message_queue.next_write = next;
    // TODO: some locking
}

pub fn receive_message(message_queue: *volatile MessageQueue) !Message {
    const original_next = message_queue.next_read;
    const new_next = (original_next + 1) % @intCast(u32, message_queue.messages.len);
    if (original_next != message_queue.next_write) {
        // TODO: Use atomics here
        if (@cmpxchgStrong(@TypeOf(message_queue.next_read), &message_queue.next_read, original_next, new_next, .SeqCst, .SeqCst) == null) {
            const message = message_queue.messages[original_next];
            message_queue.completed += 1;
            return message;
        }
    }

    @panic("wtf");
}
