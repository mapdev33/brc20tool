package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/minchenzz/brc20tool/pkg/btcapi"
	"github.com/minchenzz/brc20tool/pkg/btcapi/mempool"
	"github.com/pkg/errors"
	"testing"
)

func Test_01(t *testing.T) {
	recoverPubkey(t)
}
func Test_02(t *testing.T) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		panic(err)
	}
	// Generate the tweaked public key using the x value as the
	// script root.
	tweakedPub := txscript.ComputeTaprootKeyNoScript(privKey.PubKey())

	// Now we'll generate the corresponding tweaked private key.
	tweakedPriv := txscript.TweakTaprootPrivKey(*privKey, []byte{})

	// The public key for this private key should be the same as
	// the tweaked public key we generate above.
	b := tweakedPub.IsEqual(tweakedPriv.PubKey()) &&
		bytes.Equal(
			schnorr.SerializePubKey(tweakedPub),
			schnorr.SerializePubKey(tweakedPriv.PubKey()),
		)
	fmt.Println("result", b)
}
func Test_genAddress(t *testing.T) {
	mainnetParams := &chaincfg.MainNetParams
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		panic(err)
	}

	privstr := hex.EncodeToString(privKey.Serialize())
	fmt.Println("priv1:", privstr)

	privbytes1, err := hex.DecodeString(privstr)
	if err != nil {
		panic(err)
	}
	_, pub1 := btcec.PrivKeyFromBytes(privbytes1)
	pubKey := privKey.PubKey()

	fmt.Println("pubkey is equal", pubKey.IsEqual(pub1))

	tapKey := txscript.ComputeTaprootKeyNoScript(pubKey)

	address, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(tapKey),
		mainnetParams,
	)

	fmt.Println(address)
}
func Test_03(t *testing.T) {
	mainnetParams := &chaincfg.MainNetParams
	str := "87d8848481ad30367f454d83e206da93864f4cedcf8050a9a31fcb000b37724a"
	privbytes1, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	privKey, pub1 := btcec.PrivKeyFromBytes(privbytes1)
	pubKey := privKey.PubKey()

	wifkey1, err := btcutil.NewWIF(privKey, mainnetParams, false)
	if err != nil {
		panic(err)
	}
	wifKeyStr := wifkey1.String()
	fmt.Println("wifkey:", wifKeyStr)
	wifkey2, err := btcutil.DecodeWIF(wifKeyStr)
	if err != nil {
		panic(err)
	}
	fmt.Println("wifkey1 equal wifkey2", bytes.Equal(wifkey1.SerializePubKey(), wifkey2.SerializePubKey()))

	fmt.Println("pubkey is equal", pubKey.IsEqual(pub1))

	tapKey := txscript.ComputeTaprootKeyNoScript(pubKey)

	address, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(tapKey),
		mainnetParams,
	)

	fmt.Println(address)
}
func Test_recoverTWeakPubkey(t *testing.T) {
	mainnetParams := &chaincfg.MainNetParams
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		panic(err)
	}

	commitTxAddress, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(privKey.PubKey())), mainnetParams)
	if err != nil {
		panic(err)
	}
	pkScript, err := txscript.PayToAddrScript(commitTxAddress)
	if err != nil {
		panic(err)
	}
	// recover the raw pubkey from pkscript
	pubkey1, err := computeTWeakPkOfByScript(pkScript)
	if err != nil {
		panic(err)
	}
	b0 := bytes.Equal(pubkey1, privKey.PubKey().SerializeCompressed())
	b1 := bytes.Equal(pubkey1, privKey.PubKey().SerializeUncompressed())
	pubKey0, err := schnorr.ParsePubKey(pubkey1)
	if err != nil {
		panic(err)
	}
	b2 := pubKey0.IsEqual(privKey.PubKey())
	// change the privkey
	tweakedPriv := txscript.TweakTaprootPrivKey(*privKey, []byte{})
	b3 := pubKey0.IsEqual(tweakedPriv.PubKey())
	b4 := bytes.Equal(
		schnorr.SerializePubKey(pubKey0),
		schnorr.SerializePubKey(tweakedPriv.PubKey()),
	)

	fmt.Println("b0:", b0, "b1:", b1, "b2:", b2, "b3:", b3, "b4:", b4)
}

func recoverPubkey(t *testing.T) {

	//netParams := &chaincfg.MainNetParams
	//btcApiClient := mempool.NewClient(netParams)

	client := mempool.NewClient(&chaincfg.SigNetParams)
	txId, _ := chainhash.NewHashFromStr("b752d80e97196582fd02303f76b4b886c222070323fb7ccd425f6c89f5445f6c")
	transaction, err := client.GetRawTransaction(txId)
	if err != nil {
		t.Error(err)
	} else {
		t.Log(transaction.TxHash().String())
	}

	fmt.Println("tx has witness:", transaction.HasWitness())

	for _, txin := range transaction.TxIn {
		txOut, err := getTxOutByOutPoint(&txin.PreviousOutPoint, client)
		if err != nil {
			panic(err)
		}
		sclass := txscript.GetScriptClass(txOut.PkScript)
		fmt.Println("Script Class", sclass)

		pkscript2, err := txscript.ParsePkScript(txOut.PkScript)
		if err != nil {
			fmt.Println("333", err)
		} else {
			fmt.Println("pkscript2", pkscript2.String(), "len", len(pkscript2.Script()))
		}
		fmt.Println("===========================================")
		if txscript.IsPayToTaproot(txOut.PkScript) {
			fmt.Println("is pay TR", txscript.IsPayToTaproot(txOut.PkScript))
			fmt.Println("key path", len(txin.Witness) == 1)
			fmt.Println("script path", len(txin.Witness) >= 2)

		} else {
			fmt.Println("is pubkey ", txscript.IsPayToPubKey(txOut.PkScript))

			pkscript, err := txscript.ComputePkScript(txin.SignatureScript, txin.Witness)
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Println("pkscript1", pkscript.String(), "len", len(pkscript.Script()))
				addrs, err := pkscript.Address(&chaincfg.SigNetParams)
				if err != nil {
					fmt.Println("222", err)
				} else {
					fmt.Println("Addresses01 :", addrs)
				}
			}
		}

		class, addresses, reqSigs, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, &chaincfg.SigNetParams)
		if err != nil {
			panic(err)
		}
		fmt.Println("Script Class:", class)
		fmt.Println("Addresses:", addresses)
		fmt.Println("Required Signatures:", reqSigs)
	}
}
func getTxOutByOutPoint(outPoint *wire.OutPoint, btcApiClient btcapi.BTCAPIClient) (*wire.TxOut, error) {
	tx, err := btcApiClient.GetRawTransaction(&outPoint.Hash)
	if err != nil {
		return nil, err
	}
	if int(outPoint.Index) >= len(tx.TxOut) {
		return nil, errors.New("err out point")
	}
	return tx.TxOut[outPoint.Index], nil
}

func getPreTx(tx *wire.MsgTx, btcApiClient btcapi.BTCAPIClient) (*wire.MsgTx, error) {
	return nil, nil
}

func maybeGetPkFromTx(tx *wire.MsgTx, btcApiClient btcapi.BTCAPIClient) (*btcec.PublicKey, error) {
	firstTxIn := tx.TxIn[0]
	txOut0, err := getTxOutByOutPoint(&firstTxIn.PreviousOutPoint, btcApiClient)
	if err != nil {
		fmt.Println("cann't get the pre-txout from the OutPoint", firstTxIn.PreviousOutPoint.String())
		return nil, err
	}
	// not support multisign
	if b, e := txscript.IsMultisigScript(txOut0.PkScript); e == nil {
		if b {
			fmt.Println("not support multisign, OutPoint", firstTxIn.PreviousOutPoint.String())
			return nil, errors.New("not support multisign")
		}
	}
	if txscript.IsMultisigSigScript(txOut0.PkScript) {
		fmt.Println("not support multisign, OutPoint", firstTxIn.PreviousOutPoint.String())
		return nil, errors.New("not support multisign")
	}

	if txscript.IsPayToPubKey(txOut0.PkScript) {
		pubKey, err := btcec.ParsePubKey(extractPubKey(txOut0.PkScript))
		if err != nil {
			fmt.Println("ParsePubKey error", err, "extractPk:", extractPubKey(txOut0.PkScript))
			return nil, err
		}
		return pubKey, nil
	}
	if txscript.IsPayToPubKeyHash(txOut0.PkScript) {
		pubkey, err := ComputePkByScript(firstTxIn.SignatureScript, firstTxIn.Witness)
		if err != nil {
			fmt.Println("P2PKH: ComputePkByScript error", err, "extractPk:", extractPubKey(txOut0.PkScript))
			return nil, err
		}
		pubKey, err := btcec.ParsePubKey(pubkey)
		if err != nil {
			fmt.Println("P2PKH: ParsePubKey error", err, "pubkey:", hex.EncodeToString(pubkey))
			return nil, err
		}
		return pubKey, nil
	}
	if txscript.IsPayToScriptHash(txOut0.PkScript) {
		pubkey, err := ComputePkByScript(firstTxIn.SignatureScript, firstTxIn.Witness)
		if err != nil {
			fmt.Println("P2SH:ComputePkByScript error", err, "extractPk:", extractPubKey(txOut0.PkScript))
			return nil, err
		}
		pubKey, err := btcec.ParsePubKey(pubkey)
		if err != nil {
			fmt.Println("P2SH: ParsePubKey error", err, "pubkey:", hex.EncodeToString(pubkey))
			return nil, err
		}
		return pubKey, nil
	}
	if txscript.IsPayToWitnessPubKeyHash(txOut0.PkScript) {
		pubkey, err := ComputePkByScript(firstTxIn.SignatureScript, firstTxIn.Witness)
		if err != nil {
			fmt.Println("P2WPKH:ComputePkByScript error", err, "extractPk:", extractPubKey(txOut0.PkScript))
			return nil, err
		}
		pubKey, err := btcec.ParsePubKey(pubkey)
		if err != nil {
			fmt.Println("P2WPKH: ParsePubKey error", err, "pubkey:", hex.EncodeToString(pubkey))
			return nil, err
		}
		return pubKey, nil
	}
	if txscript.IsPayToWitnessScriptHash(txOut0.PkScript) {
		pubkey, err := ComputePkByScript(firstTxIn.SignatureScript, firstTxIn.Witness)
		if err != nil {
			fmt.Println("P2WSH:ComputePkByScript error", err, "extractPk:", extractPubKey(txOut0.PkScript))
			return nil, err
		}
		pubKey, err := btcec.ParsePubKey(pubkey)
		if err != nil {
			fmt.Println("P2WSH: ParsePubKey error", err, "pubkey:", hex.EncodeToString(pubkey))
			return nil, err
		}
		return pubKey, nil
	}
	if txscript.IsPayToTaproot(txOut0.PkScript) {

	}
	return nil, nil
}

////////////////////////////////////////////////////////////////////////////////

// extractCompressedPubKey extracts a compressed public key from the passed
// script if it is a standard pay-to-compressed-secp256k1-pubkey script.  It
// will return nil otherwise.
func extractCompressedPubKey(script []byte) []byte {
	// A pay-to-compressed-pubkey script is of the form:
	//  OP_DATA_33 <33-byte compressed pubkey> OP_CHECKSIG

	// All compressed secp256k1 public keys must start with 0x02 or 0x03.
	if len(script) == 35 &&
		script[34] == txscript.OP_CHECKSIG &&
		script[0] == txscript.OP_DATA_33 &&
		(script[1] == 0x02 || script[1] == 0x03) {

		return script[1:34]
	}

	return nil
}

// extractUncompressedPubKey extracts an uncompressed public key from the
// passed script if it is a standard pay-to-uncompressed-secp256k1-pubkey
// script.  It will return nil otherwise.
func extractUncompressedPubKey(script []byte) []byte {
	// A pay-to-uncompressed-pubkey script is of the form:
	//   OP_DATA_65 <65-byte uncompressed pubkey> OP_CHECKSIG
	//
	// All non-hybrid uncompressed secp256k1 public keys must start with 0x04.
	// Hybrid uncompressed secp256k1 public keys start with 0x06 or 0x07:
	//   - 0x06 => hybrid format for even Y coords
	//   - 0x07 => hybrid format for odd Y coords
	if len(script) == 67 &&
		script[66] == txscript.OP_CHECKSIG &&
		script[0] == txscript.OP_DATA_65 &&
		(script[1] == 0x04 || script[1] == 0x06 || script[1] == 0x07) {

		return script[1:66]
	}
	return nil
}

// extractPubKey extracts either compressed or uncompressed public key from the
// passed script if it is a either a standard pay-to-compressed-secp256k1-pubkey
// or pay-to-uncompressed-secp256k1-pubkey script, respectively.  It will return
// nil otherwise.
func extractPubKey(script []byte) []byte {
	if pubKey := extractCompressedPubKey(script); pubKey != nil {
		return pubKey
	}
	return extractUncompressedPubKey(script)
}

// ComputePkScript computes the PK of an output by looking at the spending
// input's signature script or witness.
//
// NOTE: Only P2PKH, P2SH, P2WSH, and P2WPKH redeem scripts are supported.
func ComputePkByScript(sigScript []byte, witness wire.TxWitness) ([]byte, error) {
	switch {
	case len(sigScript) > 0:
		return computeNonWitnessPkScript(sigScript)
	case len(witness) > 0:
		return computeWitnessPkScript(witness)
	default:
		return nil, txscript.ErrUnsupportedScriptType
	}
}

// minPubKeyHashSigScriptLen is the minimum length of a signature script
// that spends a P2PKH output. The length is composed of the following:
//   Signature length (1 byte)
//   Signature (min 8 bytes)
//   Signature hash type (1 byte)
//   Public key length (1 byte)
//   Public key (33 byte)
// minPubKeyHashSigScriptLen = 1 + ecdsa.MinSigLen + 1 + 1 + 33

// maxPubKeyHashSigScriptLen is the maximum length of a signature script
// that spends a P2PKH output. The length is composed of the following:
//   Signature length (1 byte)
//   Signature (max 72 bytes)
//   Signature hash type (1 byte)
//   Public key length (1 byte)
//   Public key (33 byte)
// maxPubKeyHashSigScriptLen = 1 + 72 + 1 + 1 + 33

var (
	minPubKeyHashSigScriptLen = 1 + ecdsa.MinSigLen + 1 + 1 + 33
	maxPubKeyHashSigScriptLen = 1 + 72 + 1 + 1 + 33
	// compressedPubKeyLen is the length in bytes of a compressed public
	// key.
	compressedPubKeyLen = 33
	// witnessV1TaprootLen is the length of a P2TR script.
	witnessV1TaprootLen = 34
)

// computeNonWitnessPkScript computes the PK of an output by looking at the
// spending input's signature script.
func computeNonWitnessPkScript(sigScript []byte) ([]byte, error) {

	switch {
	// Since we only support P2PKH and P2SH scripts as the only non-witness
	// script types, we should expect to see a push only script.
	case !txscript.IsPushOnlyScript(sigScript):
		return nil, txscript.ErrUnsupportedScriptType

	// If a signature script is provided with a length long enough to
	// represent a P2PKH script, then we'll attempt to parse the compressed
	// public key from it.
	case len(sigScript) >= minPubKeyHashSigScriptLen &&
		len(sigScript) <= maxPubKeyHashSigScriptLen:

		// The public key should be found as the last part of the
		// signature script. We'll attempt to parse it to ensure this is
		// a P2PKH redeem script.
		pubKey := sigScript[len(sigScript)-compressedPubKeyLen:]
		if btcec.IsCompressedPubKey(pubKey) {
			return pubKey, nil
		}

		fallthrough

	// If we failed to parse a compressed public key from the script in the
	// case above, or if the script length is not that of a P2PKH one, we
	// can assume it's a P2SH signature script.
	default:
		// The redeem script will always be the last data push of the
		// signature script, so we'll parse the script into opcodes to
		// obtain it.
		const scriptVersion = 0
		//err := checkScriptParses(scriptVersion, sigScript)
		//if err != nil {
		//	return nil, err
		//}
		//redeemScript := finalOpcodeData(scriptVersion, sigScript)
		//
		//scriptHash := hash160(redeemScript)
		//script, err := payToScriptHashScript(scriptHash)
		//if err != nil {
		//	return nil, err
		//}

		return nil, txscript.ErrUnsupportedScriptType
	}
}

// computeWitnessPkScript computes the PK of an output by looking at the
// spending input's witness.
func computeWitnessPkScript(witness wire.TxWitness) ([]byte, error) {
	// We'll use the last item of the witness stack to determine the proper
	// witness type.
	lastWitnessItem := witness[len(witness)-1]

	switch {
	// If the witness stack has a size of 2 and its last item is a
	// compressed public key, then this is a P2WPKH witness.
	case len(witness) == 2 && len(lastWitnessItem) == compressedPubKeyLen:
		pubkey := lastWitnessItem
		return pubkey, nil

	// For any other witnesses, we'll assume it's a P2WSH witness.
	default:
		//scriptHash := sha256.Sum256(lastWitnessItem)
		//script, err := payToWitnessScriptHashScript(scriptHash[:])
		//if err != nil {
		//	return nil, err
		//}
		return nil, txscript.ErrUnsupportedScriptType
	}
}

func computePkByP2TR(witness wire.TxWitness) ([]byte, error) {
	return nil, nil
}

// computeTWeakPkOfByScript extracts the raw public key bytes script if it is
// standard pay-to-witness-script-hash v1 script.
func computeTWeakPkOfByScript(script []byte) ([]byte, error) {
	// A pay-to-witness-script-hash script is of the form:
	//   OP_1 OP_DATA_32 <32-byte-hash>
	if len(script) == witnessV1TaprootLen &&
		script[0] == txscript.OP_1 &&
		script[1] == txscript.OP_DATA_32 {

		return script[2:34], nil
	}
	return nil, txscript.ErrUnsupportedScriptType
}
