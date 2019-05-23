#ifndef __BE_QUIC_BLOCK_H__
#define __BE_QUIC_BLOCK_H__

#include <vector>
#include <stdint.h>
#include <memory>

namespace net {

const int kMinRequestBlockSize      = 32 * 1024;
const int kDefaultRequestBlockSize  = 1024 * 1024;

/////////////////////////////////////BeQuicBlock/////////////////////////////////////
class BeQuicBlock {
public:
    BeQuicBlock(int64_t offset, int bytes, int threshold);
    virtual ~BeQuicBlock();

public:
    int  produce(int bytes);
    int  consume(int bytes);
    bool seek(int64_t offset);
    void reset();

    void get_range(int64_t& start, int64_t& end);

    bool completed();
    bool drained();
    bool reach_threshold();

    int64_t offset() { return offset_; }
    int  size()      { return size_; }
    int  produced()  { return produced_; }
    int  consumed()  { return consumed_; }
    int  free()      { return size_ - produced_; }
    int  available() { return produced_ - consumed_; }

private:
    int64_t offset_ = 0;
    int size_       = 0;
    int threshold_  = 0;
    int produced_   = 0;
    int consumed_   = 0;
};

/////////////////////////////////////BeQuicBlockPreloadDelegate/////////////////////////////////////
class BeQuicBlockPreloadDelegate {
public:
    BeQuicBlockPreloadDelegate() = default;
    virtual ~BeQuicBlockPreloadDelegate() = default;

public:
    virtual bool on_preload_range(int64_t start, int64_t end) = 0;
};

/////////////////////////////////////BeQuicBlockManager/////////////////////////////////////
class BeQuicBlockManager {
public:
    BeQuicBlockManager(std::shared_ptr<BeQuicBlockPreloadDelegate> preload_delegate_);
    virtual ~BeQuicBlockManager();

public:
    bool init(int64_t file_size, int block_size, int block_threshold);
    int  produce(int bytes);
    int  consume(int bytes);
    bool check_next_produce_block();
    bool check_next_consume_block();
    bool check_preload();
    bool seek(int64_t offset);

private:
    bool in_buffer(int64_t offset);

public:
    std::vector<BeQuicBlock> blocks_;
    int current_produce_block_index_ = 0;
    int current_consume_block_index_ = 0;
    int file_size_  = 0;
    int block_size_ = 0;

    std::weak_ptr<BeQuicBlockPreloadDelegate> preload_delegate_;
};

}  // namespace net

#endif  // __BE_QUIC_BLOCK_H__
