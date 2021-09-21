SUBDIRS = CTesterLib src test

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@
	
	
.PHONY: all $(SUBDIRS) clean
