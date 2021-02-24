package casext

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"github.com/opencontainers/umoci/oci/cas/dir"
)


func Fuzz(data []byte) int {
	ctx := context.Background()
	root, err := ioutil.TempDir("", "umoci-TestEngineBlobJSON")
	if err != nil {
		return -1
	}
	defer os.RemoveAll(root)

	image := filepath.Join(root, "image")
	if err := dir.Create(image); err != nil {
		return -1
	}

	engine, err := dir.Open(image)
	if err != nil {
		return -1
	}
	engineExt := NewEngine(engine)
	defer engine.Close()

	digest, _, err := engineExt.PutBlobJSON(ctx, string(data))
	if err != nil {
		return 0
	}
	blobReader, err := engine.GetBlob(ctx, digest)
	if err != nil {
		return 0
	}
	defer blobReader.Close()

	_, err = ioutil.ReadAll(blobReader)
	if err != nil {
		return 0
	}
	return 1
}
