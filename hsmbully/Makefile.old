all: hsmbully

clean:
	rm -f hsmbully
	make -C src clean

hsmbully: src/thorough-hsmbully
	cp src/thorough-hsmbully ./hsmbully

src/thorough-hsmbully:
	make -C src all

