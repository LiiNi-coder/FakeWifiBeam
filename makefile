# 변수 설정
CXX = g++
CXXFLAGS = -Wall -g
LIBS = -lpcap -lgtest -lgtest_main
TARGET = beacon-flood
SRC = main.cpp

# 기본 타겟 설정
all: $(TARGET)

# 컴파일 규칙
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

# clean 타겟
clean:
	rm -f $(TARGET)