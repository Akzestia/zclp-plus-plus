#include "center_db.h"
#include <stdexcept>

namespace center_db {
void init() {
    /*
        Init scylla client

        Must throw std::runtime_error if fail to init
    */

    throw std::runtime_error("Failed to init Center Db");
}

RequestSession::RequestSession() noexcept
    : session(cass_session_new()),
      cluster(cass_cluster_new()),
      connect_future(nullptr),
      statement(nullptr),
      result_future(nullptr),
      result(nullptr),
      iterator(nullptr) {
}

RequestSession::~RequestSession() noexcept {
    if (iterator)
        cass_iterator_free(iterator);
    if (result)
        cass_result_free(result);

    if (result_future)
        cass_future_free(result_future);

    if (statement)
        cass_statement_free(statement);

    if (connect_future)
        cass_future_free(connect_future);

    if (session)
        cass_session_free(session);

    if (cluster)
        cass_cluster_free(cluster);
}

RequestSession create_request() {
    return RequestSession();
}

void free_request(RequestSession& request) {
    if (request.iterator)
        cass_iterator_free(request.iterator);
    if (request.result)
        cass_result_free(request.result);

    if (request.result_future)
        cass_future_free(request.result_future);

    if (request.statement)
        cass_statement_free(request.statement);

    if (request.connect_future)
        cass_future_free(request.connect_future);

    if (request.session)
        cass_session_free(request.session);

    if (request.cluster)
        cass_cluster_free(request.cluster);
}

}  // namespace center_db
