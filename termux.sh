if [[ -d p2p ]]; then
	cd p2p
	git pull --ff-only
else
	git clone https://github.com/peertopeernetwork/p2p
	cd p2p
fi

apt update && apt full-upgrade && apt autoremove --purge -y
apt install -y python automake git binutils tor

echo "Starting tor..."
tor --ControlPort 9051 --CookieAuthentication 1 >/dev/null &

echo "Starting the Peer-to-Peer Network…"
./env.sh
cd ..
