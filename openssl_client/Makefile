BASEDIR  = ./
INCLUDES = -I./openssl-1.1.1/include -I. -I$(BASEDIR)
TARGET   = oc
CXX      = g++ -g -Wall -std=c++11
CXXFLAGS = $(INCLUDES)
CXXLIBS  =  -L ./openssl-1.1.1 -lssl -lcrypto

.SUFFIXES: .cpp

.cpp.o:
	$(CXX) $(CXXFLAGS) -c $<

.cpp :
	$(CXX) $(CXXFLAGS) $< -o $@ -lm $(TLIB) -lg++

SRC = test.cpp OpenSSLClient.cpp
OBJ = $(addsuffix .o, $(basename $(SRC)))

all : $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJ) $(CXXLIBS)

debug:  $(OBJ)
	$(CXX) -g $(CXXFLAGS) -o $(TARGET) $(OBJ)

depend:
	$(CXXFLAGS) -Y $(SRC)

clean:
	rm -f $(OBJ)
	rm -f $(TARGET)
