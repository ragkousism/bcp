# Broadcast Copy

Any easy way to copy files between terminals or computers on a local network.

Note: bcp currently assumes a trusted network, use with caution.

# Security model (planned)

bcp will keep the broadcast discovery model and stay lightweight, but will add:

- Integrity: receiver verifies the file hash matches what the sender advertised.
- Sender authentication: Ed25519 signatures prevent man-in-the-middle tampering.
- No encryption: anyone on the LAN can still read the file contents.

Trust model: TOFU (Trust On First Use). The first time a sender key is seen,
the receiver can trust it and store it in `~/.config/bcp/known_hosts`. After
that, the sender key must match or the transfer is rejected.

Legacy/unauthenticated transfers will be rejected by default, with an explicit
`--allow-unauth` flag to opt in.

# Performance notes (planned)

On low-power devices (e.g., Raspberry Pi 1), hashing large files dominates CPU
time. Ed25519 signing/verification happens once per transfer and is typically
small compared to streaming the file hash.

# Benchmarks (planned)

We will publish simple end-to-end benchmarks that capture throughput, CPU
usage, wall time, and peak memory. Planned test sizes include 64 KB, 1 MB,
100 MB, and 1 GB, measured on a Raspberry Pi 1 and a typical desktop/laptop.
Results and raw logs will live under a `bench/` folder.

Quick start:

	$ bench/run_bench.sh receiver ./bcp 64k 1m
	$ bench/run_bench.sh sender   ./bcp 64k 1m

# Portability (planned)

Keep the C code portable and minimal:

- Stick to C89/C99 and POSIX sockets.
- Avoid compiler-specific extensions.
- Embed small crypto sources (Ed25519 + hash) to avoid heavy deps.
- Keep OS-specific behavior behind small `#ifdef` blocks.

# Compiling

make
or
cc -D_FILE_OFFSET_BITS=64 -DED25519_REFHASH -DED25519_CUSTOMRANDOM \\
  -Ivendor/ed25519-donna -Icrypto -o bcp \\
  bcp.c crypto/sha256.c vendor/ed25519-donna/ed25519.c

# Installation

```
$ make install
```

 One line install:
```
$ bash -c "mkdir /tmp/bcp && cd /tmp/bcp && curl -L# https://github.com/jgallen23/bcp/archive/master.tar.gz | tar zx --strip 1 && make install"
```

In OSX, you can use @gil's homebrew solution: https://github.com/gil/homebrew-bcp

# Usage

To make file availabe for copying:

	$ ./bcp filename

To receive the file:

	$ ./bcp

# Planned flags / commands

	$ bcp --gen-key
	$ bcp --trust <fingerprint> [--label name]
	$ bcp --known-hosts <path>
	$ bcp --allow-unauth


# Example

Sender

	diginux@heisenberg:~/code/bcp/test$ ./bcp awesome.jpg
	Listening for request..
	Sending file to: 192.168.2.12:10789
	Sent 107545
	File sent.

Recipient

	Jordans-MacBook-Pro:bcp diginux$ ./bcp
	Requesting file..
	Incoming connection from: 192.168.2.12
	Receive: 107545
	File received: awesome.jpg

# Trust store (planned)

Trusted sender keys live in `~/.config/bcp/known_hosts`. In non-interactive
environments (no TTY), the receiver will refuse unknown keys unless
`--trust <fingerprint>` is provided ahead of time.

# Useful bash commands

bcpdir: to send directories

	# zip directory to /tmp and bcp it
	bcpdir() {

		curr_time=`date +%s`
		file=/tmp/files_$curr_time.zip

		if [[ -d $1 ]]; then

			# dir	
			cd $1
			zip -r -9 $2 $file .

		elif [[ -f $1 ]]; then
	
			# single file
			file_dir=`dirname $1`
			file_name=`basename $1`
			cd $file_dir
			zip -r -9 $2 $file $file_name

		else
			echo "$1 is not valid!"
			exit 1	
		fi

		bcp $file
		rm $file
		cd -
	}

bcppass: to send files/directories protected with password

	# zip file/directory with password to /tmp and bcp it
	bcppass() {
		bcpdir $1 -e
	}

# Alternatives:

* A great (more robust) program that uses polling: http://www.fefe.de/ncp/

* Another great approach, requires knowing name of sent file: https://www.udpcast.linux.lu/cmdlinedoc.html

* Quick file distribution challenge: http://www.advogato.org/article/555.html
