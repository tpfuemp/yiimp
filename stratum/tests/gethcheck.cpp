// gethcheck: GETH-family support in the stratum
//  - EVM address validation (GETH nodes have no validateaddress RPC)
//  - JSON-RPC 2.0 request framing (Parallax rejects requests without it)

#include "../stratum.h"

#include <cstdio>
#include <cstring>

namespace
{

int failures = 0;

void check(bool ok, const char *label)
{
	if (!ok) {
		fprintf(stderr, "FAIL %s\n", label);
		failures++;
	}
}

void test_geth_address()
{
	check(geth_valid_address("0x72b546804152cdcd3756c694722b27d3cc4eefc3"), "lowercase address");
	check(geth_valid_address("0x72B546804152CDCD3756C694722B27D3CC4EEFC3"), "uppercase hex digits");
	check(geth_valid_address("0X72b546804152cdcd3756c694722b27d3cc4eefc3"), "uppercase 0X prefix");

	check(!geth_valid_address(""), "empty address");
	check(!geth_valid_address(NULL), "null address");
	check(!geth_valid_address("72b546804152cdcd3756c694722b27d3cc4eefc3"), "no 0x prefix");
	check(!geth_valid_address("0x72b546804152cdcd3756c694722b27d3cc4eef"), "too short");
	check(!geth_valid_address("0x72b546804152cdcd3756c694722b27d3cc4eefc3ff"), "too long");
	check(!geth_valid_address("0x72b546804152cdcd3756c694722b27d3cc4eefg3"), "non-hex letter");
	check(!geth_valid_address("0x72b546804152cdcd3756c694722b27d3cc4eefc-"), "non-hex punctuation");
}

void test_rpc_request()
{
	char msg[512];

	rpc_build_request(msg, sizeof(msg), "eth_blockNumber", NULL, 7, true);
	check(!strcmp(msg, "{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"id\":\"7\"}"), "2.0 without params");

	rpc_build_request(msg, sizeof(msg), "xhash_getWork", "[]", 8, true);
	check(!strcmp(msg, "{\"jsonrpc\":\"2.0\",\"method\":\"xhash_getWork\",\"params\":[],\"id\":\"8\"}"), "2.0 with params");

	rpc_build_request(msg, sizeof(msg), "getblocktemplate", "[{}]", 9, false);
	check(!strcmp(msg, "{\"method\":\"getblocktemplate\",\"params\":[{}],\"id\":\"9\"}"), "1.0 unchanged");

	YAAMP_COIND *coind = new YAAMP_COIND();
	strcpy(coind->rpcencoding, "GETH");
	check(coind_is_geth(coind), "GETH encoding");
	strcpy(coind->rpcencoding, "POW");
	check(!coind_is_geth(coind), "POW encoding");
	delete coind;
}

} // namespace

int main(int argc, char **argv)
{
	test_geth_address();
	test_rpc_request();

	if (failures) {
		fprintf(stderr, "gethcheck: %d failure(s)\n", failures);
		return 1;
	}
	printf("gethcheck: address and RPC framing ok\n");
	return 0;
}
