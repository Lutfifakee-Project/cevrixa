package cli

import (
	"fmt"
	"io"
)

const bannerArt = "  ________ _   _______(_)  ______ _\n" +
	" / ___/ _ \\ | / / ___/ / |/_/ __ `/\n" +
	"/ /__/  __/ |/ / /  / />  </ /_/ /\n" +
	"\\___/\\___/|___/_/  /_/_/|_|\\__,_/"

func writeBanner(w io.Writer) {
	fmt.Fprintf(w, "%s %s\n\n", bannerArt, Version)
}
