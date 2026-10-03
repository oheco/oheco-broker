/* Local SDK relay-only regression. No sockets, server, or credentials. */
#include "agent.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr); exit(1); \
} } while (0)

static int received;
static void receive_cb(juice_agent_t *a, const char *data, size_t size, void *user)
{
    (void)a;
    (void)data;
    (void)size;
    (void)user;
    ++received;
}

static addr_record_t address(uint16_t port)
{
    addr_record_t record = {0};
    struct sockaddr_in *sin = (struct sockaddr_in *)&record.addr;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin->sin_port = htons(port);
    record.len = sizeof(*sin);
    record.socktype = SOCK_DGRAM;
    return record;
}

int main(void)
{
    juice_config_t config = {0};
    config.relay_only = true;
    config.cb_recv = receive_cb;
    juice_agent_t *agent = juice_create(&config);
    REQUIRE(agent && agent->config.relay_only);
    addr_record_t lr = address(31401), rr = address(31402);
    ice_candidate_t local, remote;
    REQUIRE(!ice_create_local_candidate(ICE_CANDIDATE_TYPE_HOST, 1, 0,
        &rr, &remote, ICE_CANDIDATE_TRANSPORT_UDP));
    REQUIRE(!agent_add_candidate_pair(agent, NULL, &remote));
    REQUIRE(agent->candidate_pairs_count == 0);
    ice_candidate_type_t direct[] = {ICE_CANDIDATE_TYPE_HOST,
        ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE};
    for (size_t i = 0; i < sizeof(direct)/sizeof(direct[0]); ++i) {
        REQUIRE(!ice_create_local_candidate(direct[i], 1, 0, &lr,
            &local, ICE_CANDIDATE_TRANSPORT_UDP));
        REQUIRE(!agent_add_candidate_pair(agent, &local, &remote));
        REQUIRE(agent->candidate_pairs_count == 0);
    }
    REQUIRE(!agent_add_remote_reflexive_candidate(agent,
        ICE_CANDIDATE_TYPE_PEER_REFLEXIVE, 100, &rr));
    REQUIRE(agent->candidate_pairs_count == 0);

    REQUIRE(!ice_create_local_candidate(ICE_CANDIDATE_TYPE_RELAYED, 1, 0,
        &lr, &local, ICE_CANDIDATE_TRANSPORT_UDP));
    remote.transport = ICE_CANDIDATE_TRANSPORT_TCP_TYPE_PASSIVE;
    REQUIRE(!agent_add_candidate_pair(agent, &local, &remote));
    REQUIRE(agent->candidate_pairs_count == 0);
    remote.transport = ICE_CANDIDATE_TRANSPORT_UDP;
    agent->entries[0].type = AGENT_STUN_ENTRY_TYPE_RELAY;
    agent->entries[0].relayed = lr;
    agent->entries_count = 1;
    REQUIRE(!agent_add_candidate_pair(agent, &local, &remote));
    REQUIRE(agent->candidate_pairs_count == 1 && agent->entries_count == 2);
    REQUIRE(agent->candidate_pairs[0].local->type == ICE_CANDIDATE_TYPE_RELAYED);
    REQUIRE(agent->entries[1].relay_entry == &agent->entries[0]);

    /* Even a direct packet with a known peer address must not reach cb_recv. */
    agent->state = JUICE_STATE_CONNECTED;
    char data[] = "application probe";
    REQUIRE(agent_input(agent, data, sizeof(data), &rr, NULL) < 0);
    REQUIRE(received == 0);
    REQUIRE(agent_input(agent, data, sizeof(data), &rr, &lr) == 0);
    REQUIRE(received == 1);
    stun_message_t check = {0};
    check.msg_method = STUN_METHOD_BINDING;
    check.has_integrity = true;
    REQUIRE(agent_dispatch_stun(agent, data, sizeof(data), &check, &rr, NULL) < 0);
    juice_destroy(agent);

    /* Default configuration still admits direct pairs; forced send is guarded
     * even if a future code path were to introduce an invalid selection. */
    config.relay_only = false;
    agent = juice_create(&config);
    REQUIRE(agent && !agent->config.relay_only);
    REQUIRE(!agent_add_candidate_pair(agent, NULL, &remote));
    REQUIRE(agent->candidate_pairs_count == 1);
    atomic_store(&agent->selected_entry, &agent->entries[0]);
    agent->config.relay_only = true;
    REQUIRE(agent_send(agent, data, sizeof(data), 0) < 0);
    juice_destroy(agent);
    puts("PASS libjuice relay-only pair policy/default/peer-reflexive/inbound/outbound guards");
    return 0;
}
