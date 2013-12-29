set -e
set -u

# If you DON'T have espresso installed (Unix) or you don't want to use it, you can use

g++ -Wall -std=c++0x -O2 -o main main.cc -lboost_program_options
g++ -Wall -std=c++0x -O2 -o verify-preimage verify-preimage.cc

# If you have espresso installed (Unix), you can use

# g++ -DENABLE_HALFADDER_VIA_ESPRESSO=1 -Wall -std=c++0x -O2 -o main main.cc -lboost_program_options
# g++ -DENABLE_HALFADDER_VIA_ESPRESSO=1 -Wall -std=c++0x -O2 -o verify-preimage verify-preimage.cc

