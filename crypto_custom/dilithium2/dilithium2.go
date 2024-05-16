package dilithium2

import (
	"crypto"
	"io"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

type Dilithium2PublicKey struct {
	Value []byte
}

type Dilithium2PrivateKey struct {
	Dilithium2PublicKey Dilithium2PublicKey
	Secret              oqs.Signature
	publicKeyGenerated  bool
}

func (priv Dilithium2PrivateKey) Public() crypto.PublicKey {
	if !priv.publicKeyGenerated {
		sig := oqs.Signature{}
		if err := sig.Init("Dilithium2", nil); err != nil {
			return nil
		}
		publicKey, err := sig.GenerateKeyPair()
		priv.Secret = sig
		//print("Secreto" + string(priv.Secret))
		if err != nil {

			return nil
		}

		priv.Dilithium2PublicKey.Value = publicKey
		priv.publicKeyGenerated = true
	}
	return priv.Dilithium2PublicKey
}

func GenerateKeyPair() *Dilithium2PrivateKey {
	sig := oqs.Signature{}
	sig.Init("Dilithium2", nil)

	key := Dilithium2PrivateKey{}

	publicKey, _ := sig.GenerateKeyPair()
	key.Dilithium2PublicKey.Value = publicKey
	key.Secret = sig
	key.publicKeyGenerated = true

	return &key
}

func (priv Dilithium2PrivateKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	signature, err := priv.Secret.Sign(digest)
	if err != nil {
		print("ERROR FIRMANDO")
		return nil, err
	}
	return signature, nil
}
