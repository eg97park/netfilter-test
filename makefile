TARGET=netfilter-test
LDLIBS=-lnetfilter_queue

all: $(TARGET)

bm.o: bm.h bm.c

$(TARGET): bm.o main.o
	$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@ -g

clean:
	rm -f $(TARGET) *.o
