#####################
### Configuration ###
#####################
TARGET_NAME=ssl_demo

# List all source files here.
# These are assumed to be in SRCDIR.
SRC=main.c

SRCDIR=src
OBJDIR=obj
BINDIR=bin

CFLAGS=-Wall
# LDFLAGS=-lopenssl

CC=gcc



##################
### Auto setup ###
##################
TARGET=$(BINDIR)/$(TARGET_NAME)
obj = $(call c_to_o,$(SRC))
OBJ = $(addprefix $(OBJDIR)/,$(obj))



###########################################
### Helper functions ###
#
# These must be placed before make targets.
###########################################
# Convert a .c extension to a .o extension
c_to_o=$(call convert_extension,.c,.o,$1)

# $1 is the initial extension
# $2 is the final extension
# $3 is the file in question
convert_extension = $(patsubst %$1,%$2,$3)



###############
### Targets ###
###############
.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	@mkdir -p $(BINDIR)
	$(CC) $^ -o $@ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -rf $(OBJDIR) $(TARGET)



#####################
### Documentation ###
#####################
# $@	the name of the target
# $<	the name of the first prerequisite
# $^	the names of all prerequisites separated by a space
# % 	match this pattern
