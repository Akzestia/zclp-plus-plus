#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace tokio {

class ThreadPool {
  private:
    struct Worker {
        std::atomic<bool> available{true};
        std::thread thread;
        std::queue<std::function<void()>> tasks;
        std::mutex task_mutex;
        std::condition_variable cv;
        bool stop{false};
    };

    std::vector<std::unique_ptr<Worker>> workers;
    std::mutex pool_mutex;

  public:
    ThreadPool(size_t num_threads) {
        workers.reserve(num_threads);

        for (size_t i = 0; i < num_threads; i++) {
            auto worker = std::make_unique<Worker>();

            worker->thread = std::thread([this, w = worker.get()]() {
                while (true) {
                    std::function<void()> task;

                    {
                        std::unique_lock<std::mutex> lock(w->task_mutex);
                        w->cv.wait(lock, [w]() {
                            return !w->tasks.empty() || w->stop;
                        });

                        if (w->stop && w->tasks.empty()) {
                            return;
                        }

                        task = std::move(w->tasks.front());
                        w->tasks.pop();
                    }

                    w->available.store(false);
                    task();
                    w->available.store(true);
                }
            });

            workers.push_back(std::move(worker));
        }
    }

    template<typename F>
    void assign_task(F&& task) {
        std::lock_guard<std::mutex> lock(pool_mutex);

        Worker* least_busy = nullptr;
        size_t min_tasks = std::numeric_limits<size_t>::max();

        auto begin = workers.begin();
        auto end = workers.end();

        while (begin != end) {
            const auto& worker = *begin;
            std::lock_guard<std::mutex> worker_lock(worker->task_mutex);
            if (worker->tasks.size() < min_tasks) {
                min_tasks = worker->tasks.size();
                least_busy = worker.get();
                if (worker->available.load() && worker->tasks.empty()) {
                    break;
                }
            }
            begin++;
        }
        if (least_busy) {
            std::lock_guard<std::mutex> worker_lock(least_busy->task_mutex);
            least_busy->tasks.push(std::forward<F>(task));
            least_busy->cv.notify_one();
        }
    }

    ~ThreadPool() {
        auto begin = workers.begin();
        auto end = workers.end();

        while (begin != end) {
            auto& worker = *begin;
            {
                std::lock_guard<std::mutex> lock(worker->task_mutex);
                worker->stop = true;
            }
            worker->cv.notify_one();
            worker->thread.join();
            begin++;
        }
    }
};

}  // namespace tokio
