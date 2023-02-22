import binascii

from stellar_sdk import xdr as stellar_xdr
from stellar_sdk.soroban import SorobanServer
from stellar_sdk.soroban_types.address import Address

rpc_server_url = "https://horizon-futurenet.stellar.cash/soroban/rpc"

contract_id = "8542841a633aafc771f07bc472b7a799fa2e82cced417356505f569daaaedc47"
account_id = "GBMLPRFCZDZJPKUPHUSHCKA737GOZL7ERZLGGMJ6YGHBFJZ6ZKMKCZTM"


def get_address_nonce():
    ledger_key = stellar_xdr.LedgerKey.from_contract_data(
        stellar_xdr.LedgerKeyContractData(
            contract_id=stellar_xdr.Hash(binascii.unhexlify(contract_id)),
            key=stellar_xdr.SCVal.from_scv_object(
                stellar_xdr.SCObject.from_sco_nonce_key(
                    Address(account_id)._to_xdr_sc_address()
                )
            ),
        )
    )
    with SorobanServer(rpc_server_url) as server:
        response = server.get_ledger_entry(ledger_key)
        print(response)


if __name__ == "__main__":
    get_address_nonce()
