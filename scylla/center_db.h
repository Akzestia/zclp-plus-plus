#include <cassandra.h>

/*
    Scylla db is only used on server side.
*/

namespace center_db {
void init();

struct RequestSession {
    CassSession* session;
    CassCluster* cluster;
    CassFuture* connect_future;
    CassStatement* statement;
    CassFuture* result_future;
    const CassResult* result;
    CassIterator* iterator;

    [[nodiscard]] RequestSession() noexcept;
    ~RequestSession() noexcept;
};

RequestSession create_request();

void free_request(RequestSession& request);

}  // namespace center_db
