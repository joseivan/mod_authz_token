MOD_NAME := mod_authz_token
MOD_DEBUG ?= n

ifeq ($(MOD_DEBUG),y)
CFLAGS += -DMOD_AUTHZ_TOKEN_DEBUG=1
endif


.PHONY: all
all: $(MOD_NAME).la

.PHONY: clean
clean:
	rm -rf .libs $(MOD_NAME).o $(MOD_NAME).so $(MOD_NAME).la $(MOD_NAME).lo $(MOD_NAME).slo

.PHONY: install
install: $(MOD_NAME).la
	apxs -i -n $(MOD_NAME) $<

$(MOD_NAME).la: $(MOD_NAME).c
	apxs -c $<
