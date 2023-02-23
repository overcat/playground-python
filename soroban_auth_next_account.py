import time
import binascii

from stellar_sdk import Network, Keypair, TransactionBuilder
from stellar_sdk import xdr as stellar_xdr
from stellar_sdk.authorized_invocation import AuthorizedInvocation
from stellar_sdk.contract_auth import ContractAuth
from stellar_sdk.soroban import SorobanServer
from stellar_sdk.soroban.soroban_rpc import TransactionStatus
from stellar_sdk.soroban_types import Uint32, Address, AccountEd25519Signature
from stellar_sdk.utils import sha256

rpc_server_url = "https://horizon-futurenet.stellar.cash:443/soroban/rpc"
soroban_server = SorobanServer(rpc_server_url)
network_passphrase = Network.FUTURENET_NETWORK_PASSPHRASE
network_id = Network(network_passphrase).network_id()

# https://github.com/stellar/soroban-examples/tree/v0.6.0/auth
contract_id = "8542841a633aafc771f07bc472b7a799fa2e82cced417356505f569daaaedc47"
tx_submitter_kp = Keypair.from_secret(
    "SAAPYAPTTRZMCUZFPG3G66V4ZMHTK4TWA6NS7U4F7Z3IMUD52EK4DDEV"
)
op_invoker_kp = Keypair.from_secret(
    "SAEZSI6DY7AXJFIYA4PM6SIBNEYYXIEM2MSOTHFGKHDW32MBQ7KVO6EN"
)

def get_nonce(account_id) -> int:
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
    try:
        response = soroban_server.get_ledger_entry(ledger_key)
        data = stellar_xdr.LedgerEntryData.from_xdr(response.xdr)
        return data.contract_data.val.obj.u64.uint64
    except:
        return 0

nonce = get_nonce(op_invoker_kp.public_key)
func_name = "increment"
args = [Address(op_invoker_kp.public_key), Uint32(10)]

# Let's build the signature manually for now, and simplify it later.
invocation = AuthorizedInvocation(
    contract_id=contract_id,
    function_name=func_name,
    args=args,
    sub_invocations=[],
)
preimage = stellar_xdr.HashIDPreimage.from_envelope_type_contract_auth(
    stellar_xdr.HashIDPreimageContractAuth(
        network_id=stellar_xdr.Hash(network_id),
        nonce=stellar_xdr.Uint64(nonce),
        invocation=invocation.to_xdr_object(),
    )
)
sig_bytes = op_invoker_kp.sign(sha256(preimage.to_xdr_bytes()))
signature = AccountEd25519Signature(op_invoker_kp, sig_bytes)

source = soroban_server.load_account(tx_submitter_kp.public_key)
tx = (
    TransactionBuilder(source, network_passphrase)
    .add_time_bounds(0, 0)
    .append_invoke_contract_function_op(
        contract_id=contract_id,
        method=func_name,
        parameters=args,
        auth=[
            ContractAuth(
                address=Address(op_invoker_kp.public_key),
                nonce=nonce,
                root_invocation=invocation,
                signature_args=[signature],
            )
        ],
    )
    .build()
)

simulate_transaction_data = soroban_server.simulate_transaction(tx)
print(f"simulated transaction: {simulate_transaction_data}")

print(f"setting footprint and signing transaction...")
assert simulate_transaction_data.results is not None
tx.set_footpoint(simulate_transaction_data.results[0].footprint)
tx.sign(tx_submitter_kp)

print(f"Signed XDR:\n{tx.to_xdr()}")

send_transaction_data = soroban_server.send_transaction(tx)
print(f"sent transaction: {send_transaction_data}")

while True:
    print("waiting for transaction to be confirmed...")
    get_transaction_status_data = soroban_server.get_transaction_status(
        send_transaction_data.id
    )
    if get_transaction_status_data.status != TransactionStatus.PENDING:
        break
    time.sleep(3)
print(f"transaction status: {get_transaction_status_data}")

if get_transaction_status_data.status == TransactionStatus.SUCCESS:
    result = stellar_xdr.SCVal.from_xdr(get_transaction_status_data.results[0].xdr)  # type: ignore
    print(f"transaction result: {result}")
