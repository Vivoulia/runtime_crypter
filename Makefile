CC = g++
src = $(wildcard *.cpp)
obj = $(src:.cpp=.o)

LDFLAGS = 

prog: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) myprog