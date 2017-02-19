CXXFLAGS = -g -Wall -Wextra -pedantic

.PHONY: clean install uninstall


metacute:*.cpp
	$(CXX) $< -o $@ $(CXXFLAGS)

clean:
	rm metacute

install:
	mv metacute /usr/bin

uninstall:
	rm /usr/bin/metacute


