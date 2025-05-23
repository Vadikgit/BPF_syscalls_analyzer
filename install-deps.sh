apt update
apt install -y git-all
apt install -y clang libelf1 libelf-dev zlib1g-dev
apt install -y llvm
apt install -y build-essential
apt install -y openssl
apt install -y libssl-dev
apt install -y libev-dev

git clone https://github.com/CopernicaMarketingSoftware/AMQP-CPP.git
cd AMQP-CPP
make
make install
cd ..

git clone https://github.com/Vadikgit/BPF_syscalls_analyzer.git
cd BPF_syscalls_analyzer/bpf_container_process_tree_builder/code
make analyzer
