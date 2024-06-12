.PHONY: all clean 

all: netcap

netcap:
	@go build

clean:
	@rm netcap -f
