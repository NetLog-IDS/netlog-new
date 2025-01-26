platform="unknown"
unameis=$(uname)

if [ $unameis = "Darwin" ]; then
    ./setup/setup.sh mac
elif [ $unameis = "Linux" ]; then
    sudo ./setup/setup.sh linux
else
    echo "Platform unsuported, handle configuration manually."
fi
