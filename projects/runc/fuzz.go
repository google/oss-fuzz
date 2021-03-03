package fuzzing

import (
	//"os"
	"runtime"
	"fmt"
	"io"
	"io/ioutil"
	//"path/filepath"
	"os/exec"
	"os"
    "net/http"
)


var busyboxTar string

func init() {
	err := os.MkdirAll("/tmp/testdata", 0755)
	if err != nil {
		fmt.Println(err)
	}
	err = os.MkdirAll("/tmp/rootfs", 0755)
	if err != nil {
		fmt.Println(err)
	}
	_, _, _, _ = runtime.Caller(0)
	files, err := ioutil.ReadDir("/tmp")
    if err != nil {
        panic(err)
    }
 
    for _, f := range files {
            fmt.Println(f.Name())
    }
	/*getImages, err := filepath.Abs("/tmp/get-images.sh")
	if err != nil {
		panic(err)
	}*/
	//_, _ = exec.Command("chmod", "+x", "/tmp/get-images.sh").CombinedOutput()
	/*out, err := exec.Command("/tmp/get-images.sh").CombinedOutput()
	if err != nil {
		panic(fmt.Errorf("run get-images.sh error %s (output: %s)", err, out))
	}*/
	url := "https://github.com/docker-library/busybox/raw/dist-arm64v8/stable/glibc/busybox.tar.xz"
	//filename := "busybox-arm64v8.tar.xz"
	err = DownloadFile(url, "/tmp/testdata/busybox-arm64v8.tar.xz")
    if err != nil {
        panic(err)
    }
   
	files, err = ioutil.ReadDir("/tmp/testdata")
    if err != nil {
        panic(err)
    }
 
    for _, f := range files {
            fmt.Println(f.Name())
    }
    busyboxTar = "/tmp/testdata/busybox-arm64v8.tar.xz"
    cmd := exec.Command("tar", "--exclude", "'./dev/*'", "-C", "/tmp/rootfs", "-xf", "/tmp/testdata/busybox-arm64v8.tar.xz")
    //cmd := exec.Command("tar", "-x", busyboxTar)
	err = cmd.Run()
	if err != nil {
		panic(err)
	}

	files, err = ioutil.ReadDir("/tmp/rootfs")
    if err != nil {
        panic(err)
    }
 
    for _, f := range files {
            fmt.Println(f.Name())
    }
}

func Fuzz(data []byte) int {
	return 1
}


// DownloadFile will download a url and store it in local filepath.
// It writes to the destination file as it downloads it, without
// loading the entire file into memory.
func DownloadFile(url string, filepath string) error {
    // Create the file
    out, err := os.Create(filepath)
    if err != nil {
        return err
    }
    defer out.Close()

    // Get the data
    resp, err := http.Get(url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    // Write the body to file
    _, err = io.Copy(out, resp.Body)
    if err != nil {
        return err
    }

    return nil
}