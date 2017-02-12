CC = g++
CFLAGS = -g -Wall -Wextra -pedantic


metacute:*.cpp
	$(CC) $< -o $@ $(CFLAGS)

clean:
	rm metacute


.PHONY: clean
