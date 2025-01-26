:: install dependencies
echo "Trying to install WinPcap..."
choco install winpcap -y
echo "Trying to install curl..."
choco install wget -y
echo "Trying to install cmake..."
choco install cmake --installargs 'ADD_CMAKE_TO_PATH=System' -y
echo "Trying to install make..."
choco install make -y

:: get winpcap developer pack
echo "Fetching WinPcap developer pack..."
mkdir ext
cd ext
wget https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip
tar -xf WpdPack_4_1_2.zip
del WpdPack_4_1_2.zip
echo "Developer pack is now in spoofy\ext\'
