#include "net/tools/quic/be_quic_block.h"
#include "base/logging.h"

namespace net {

/////////////////////////////////////BeQuicBlock/////////////////////////////////////
BeQuicBlock::BeQuicBlock(int64_t offset, int bytes, int threshold)
    : offset_(offset),
      size_(bytes),
      threshold_(threshold) {

}

BeQuicBlock::~BeQuicBlock() {

}

int BeQuicBlock::produce(int bytes) {
    int free_space = free();
    if (free_space <= 0) {
        return 0;
    }

    int produce_len = std::min<int>(free_space, bytes);
    produced_ += produce_len;
    return produce_len;
}

int BeQuicBlock::consume(int bytes) {
    int available_space = available();
    if (available_space <= 0) {
        return 0;
    }

    int consume_len = std::min<int>(available_space, bytes);
    consumed_ += consume_len;
    return consume_len;
}

bool BeQuicBlock::seek(int64_t offset) {
    if (offset >= consumed_ && offset < produced_) {
        consumed_ = offset;
        return true;
    }

    return false;
}

void BeQuicBlock::reset() {
    produced_ = 0;
    consumed_ = 0;
}

void BeQuicBlock::get_range(int64_t& start, int64_t& end) {
    start   = offset_;
    end     = offset_ + size_ - 1;
}

bool BeQuicBlock::completed() {
    return produced_ >= size_;
}

bool BeQuicBlock::drained() {
    return consumed_ >= size_;
}

bool BeQuicBlock::reach_threshold() {
    return consumed_ >= threshold_;
}

/////////////////////////////////////BeQuicBlockManager/////////////////////////////////////
BeQuicBlockManager::BeQuicBlockManager(std::shared_ptr<BeQuicBlockPreloadDelegate> preload_delegate)
    : preload_delegate_(preload_delegate) {

}

BeQuicBlockManager::~BeQuicBlockManager() {

}

bool BeQuicBlockManager::init(int64_t file_size, int block_size, int block_threshold) {
    bool ret = true;
    do {
        if (file_size <= 0) {
            LOG(ERROR) << "Invalid file size " << file_size << std::endl;
            ret = false;
            break;
        }

        if (block_size == 0) {
            LOG(INFO) << "Won't split file." << std::endl;
            ret = false;
            break;
        }

        block_size  = (block_size < 0 || block_size < kMinRequestBlockSize) ? kDefaultRequestBlockSize : block_size;
        file_size_  = file_size;
        block_size_ = block_size;

        int64_t block_offset = 0;
        while (block_offset < file_size) {
            int cur_block_size = std::min<int>((int)(file_size - block_offset), block_size);
            int threshold = (int)(cur_block_size * ((double)block_threshold / 100));
            blocks_.emplace_back(block_offset, cur_block_size, threshold);
            block_offset += cur_block_size;
        }
    } while (0);
    return ret;
}

int BeQuicBlockManager::produce(int bytes) {
    int produced = 0;
    while (bytes) {
        BeQuicBlock &block = blocks_[current_produce_block_index_];
        int ret = block.produce(bytes);
        if (ret <= 0) {
            //Should not be here.
            LOG(ERROR) << "Can't not produce in block " << current_produce_block_index_ << std::endl;
            break;
        }

        produced    += ret;
        bytes       -= ret;

        //Check if it's necessary to write into next block, if left bytes = 0 and block completed,
        //DO NOT switch to next produce block, for check_preload() may check failed, MUST preload 
        //first, and then switch to next block inside check_preload().
        if (bytes > 0 && !check_next_produce_block()) {
            break;
        }
    }

    //Check if ready to preload next block.
    if (produced > 0) {
        check_preload();
    }
    return produced;
 }

int BeQuicBlockManager::consume(int bytes) {
    int consumed = 0;
    while (bytes) {
        BeQuicBlock &block = blocks_[current_consume_block_index_];
        int ret = block.consume(bytes);
        if (ret <= 0) {
            //Should not be here, buffer should always contains enough data and then this method be called.
            LOG(ERROR) << "Can't not consume from block " << current_consume_block_index_ << std::endl;
            break;
        }

        consumed    += ret;
        bytes       -= ret;

        //Check if ready to preload next block.
        check_preload();

        //Check if next consume block ready, if left bytes = 0 and block drained, switch to next
        //block immediately for no other opportunity to do this, so check_preload() must be done
        //before this time for consume block index may have been changed.
        if (!check_next_consume_block()) {
            break;
        }
    }
    return consumed;
}

bool BeQuicBlockManager::check_next_produce_block() {
    BeQuicBlock &block = blocks_[current_produce_block_index_];
    if (block.completed() && (size_t)current_produce_block_index_ < blocks_.size() - 1) {
        current_produce_block_index_++;
        return true;
    } else {
        return false;
    }
}

bool BeQuicBlockManager::check_next_consume_block() {
    BeQuicBlock &block = blocks_[current_consume_block_index_];
    if (block.drained() && (size_t)current_consume_block_index_ < blocks_.size() - 1) {
        current_consume_block_index_++;
        return true;
    } else {
        return false;
    }
}

bool BeQuicBlockManager::check_preload() {
    bool ret = true;
    do {
        //Checking if index valid.
        if (current_produce_block_index_ != current_consume_block_index_ || (size_t)current_produce_block_index_ >= blocks_.size() - 1) {
            ret = false;
            break;
        }

        //Check if consume block downloading completed and consumed bytes reaches threshold.
        BeQuicBlock &consume_block = blocks_[current_consume_block_index_];
        bool completed          = consume_block.completed();
        bool reach_threshold    = consume_block.reach_threshold();

        if (!completed || !reach_threshold) {
            ret = false;
            break;
        }

        //Check delegate.
        std::shared_ptr<BeQuicBlockPreloadDelegate> preload_delegate = preload_delegate_.lock();
        if (preload_delegate == NULL) {
            ret = false;
            break;
        }

        //Report next block range to delegate and decide whether to increase current_produce_block_index_.
        int64_t start = -1, end = -1;
        BeQuicBlock &next_produce_block = blocks_[current_produce_block_index_ + 1];
        next_produce_block.get_range(start, end);
        next_produce_block.reset();

        if (!preload_delegate->on_preload_range(start, end)) {
            ret = false;
            break;
        }

        current_produce_block_index_++;
    } while (0);
    return ret;
}

bool BeQuicBlockManager::seek(int64_t offset) {
    bool ret = true;
    do {
        if (file_size_ <= 0 || block_size_ <= 0 || offset < 0 || offset >= file_size_) {
            ret = false;
            break;
        }

        size_t block_index = (size_t)(offset / block_size_);
        if (block_index >= blocks_.size()) {
            ret = false;
            break;
        }

        int block_offset = (int)(offset % block_size_);
        BeQuicBlock &block = blocks_[block_index];

        int64_t preload_start   = -1;
        int64_t preload_end     = -1;

        if (in_buffer(offset)) {
            //Do not move produce block index.
            current_consume_block_index_ = block_index;

            //Seek in block.
            block.seek(block_offset);

            //Preload next block if current produce block completed.
            if (blocks_[current_produce_block_index_].completed() && 
                (size_t)current_produce_block_index_ < blocks_.size() - 1) {
                BeQuicBlock& next_block = blocks_[++current_produce_block_index_];
                next_block.reset();
                preload_start   = next_block.offset();
                preload_end     = next_block.offset() + next_block.size() - 1;
            }
        } else {
            //Reset current produce and consume block.
            blocks_[current_produce_block_index_].reset();
            blocks_[current_consume_block_index_].reset();

            //Set current produce and consume block index to target block index.
            current_consume_block_index_ = block_index;
            current_produce_block_index_ = block_index;

            //Seek to block_offset inside target block.
            block.reset();
            block.produce(block_offset);
            block.consume(block_offset);

            //Counting preload range.
            preload_start   = offset;
            preload_end     = offset + block.free() - 1;

            //Append next block if current block is not a complete block.
            if (block_offset > 0 &&
                (size_t)block_index < blocks_.size() - 1) {
                BeQuicBlock& next_block = blocks_[block_index + 1];
                next_block.reset();
                preload_end += next_block.size();
            }
        }

        if (preload_end <= preload_start) {
            LOG(ERROR) << "Seek fail, bad range " << preload_start << "-" << preload_end << std::endl;
            break;
        }

        //Check to download left byte in current block and preload next block.
        std::shared_ptr<BeQuicBlockPreloadDelegate> preload_delegate = preload_delegate_.lock();
        if (preload_delegate == NULL) {
            ret = false;
            break;
        }

        if (!preload_delegate->on_preload_range(preload_start, preload_end)) {
            ret = false;
            break;
        }
    } while (0);
    return ret;
}

bool BeQuicBlockManager::in_buffer(int64_t offset) {
    BeQuicBlock &consume_block  = blocks_[current_consume_block_index_];
    BeQuicBlock &produce_block  = blocks_[current_produce_block_index_];
    int64_t buffer_begin        = consume_block.offset() + consume_block.consumed();
    int64_t buffer_end          = produce_block.offset() + produce_block.produced();

    return offset >= buffer_begin && offset < buffer_end;
}

}  // namespace net
