# All Target

PROJECT = crypto_test 
OBJS = crypto_test.o

DEPS = lib/*.h
LIB = cryptolib.a
LIB_SRC = lib/*.cpp
LIB_OBJS = lib/codec.o lib/block_cipher.o lib/cookie.o  
#$(LIB_SRC:.cpp=.o) 
#TEST = crypto_test
CXXFLAGS = -lstdc++ -lm -g -std=c++0x 
CC = g++



# Main Program
all: lib $(PROJECT)


%.o: %.cpp $(DEPS)
	$(CC) -c -o $@ $< $(CXXFLAGS) 		
	-@echo ' '		
        
$(PROJECT): $(OBJS)
		-@echo ' '
		-@echo '>> Now making main project'
		-@echo ' '
		$(CC) $(OBJS) $(LIB) -o $(PROJECT)		
		-@echo ' '
		

# Static Library
lib: $(LIB)

$(LIB): $(LIB_OBJS)
		-@echo ' '
		-@echo '>> Now making static crypto library'
		-@echo ' '
		ar -rs $(LIB) $(LIB_OBJS)

.PHONY: lib

# Test Program
#test: $(TEST)
#
#TEST_OBJS=$(TEST:.cpp=.o)

#%.o: %.cpp $(DEPS)
#	$(CC) -c -o $@ $< $(CFLAGS)
#
#$(TEST): $(TEST_OBJS).o 
#		$(CC) $(TEST_OBJS) $(LIB) -o $(TEST)	
		
		


# Other Targets
.PHONY: 
clean:
	-$(RM) $(OBJS) $(LIB_OBJS) $(PROJECT) $(LIB)
	-@echo ' '

	
	  