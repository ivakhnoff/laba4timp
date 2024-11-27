#include "cipher.h"
#include "cipher.cpp"
#include <UnitTest++/UnitTest++.h>
#include <locale>
#include <iostream>
#include <string>

SUITE(KeyTest) {
	TEST(ValidKey) 
    	{ cipher c(3);
    	CHECK_EQUAL(c.encrypt("LAGODA"), "GAADLO"); }
	TEST(InvalidKey) 
    	{ CHECK_THROW(cipher c(-2), cipher_error); }
    TEST(FloatKey) 
    	{ CHECK_THROW(cipher c(-36.6), cipher_error); }
    TEST(BigKey) 
    { 
        cipher c(100);
    	CHECK_EQUAL(c.encrypt("ADOGAL"), "LAGODA");  
    }
    
     TEST(KeyIsOne) {
        cipher c(1);
        CHECK_EQUAL("LAGODA", c.encrypt("LAGODA")); 
    }
    TEST(VeryBigKey) {
        std::string text = "LAGODA";
        cipher c(100);
        int expectedKey = std::ceil(text.length() / 2.0) + 3; 
        cipher expectedCipher(expectedKey);
        CHECK_EQUAL(expectedCipher.encrypt(text), c.encrypt(text)); 
    }
}
SUITE(EncryptTest)
{
	
    TEST(UpString) 
    { 
        cipher c(3);
        CHECK_EQUAL("UAVHMOSRN", c.encrypt("SHURMANOV"));
    }
    TEST(LowString) 
    { 
        cipher c(3);
        CHECK_EQUAL("GAADLO", c.encrypt("laGoDa"));
    }

    TEST(EmptyString) 
    { 
        cipher c(3);
        CHECK_THROW(c.encrypt(""), cipher_error);
    }

    TEST(DigestText) 
    { 
        cipher c(3);
        CHECK_EQUAL("GAADLO", c.encrypt("LAGODA1999"));
    }
    TEST(PunctuationUndSpaceText) 
    { 
        cipher c(3);
        CHECK_EQUAL("GAADLO", c.encrypt("LA GO, DA"));
    }
  
    TEST(SpaceTextBeginEnd){
        cipher c(3);
        CHECK_EQUAL("GAADLO",c.encrypt(" LAGODA   "));
    }
    
}

SUITE(DecryptTest)
{
    TEST(UpString) 
    { 
        cipher c(3);
        CHECK_EQUAL("LAGODA", c.decrypt("GAADLO")); 
    }
    TEST(LowString) 
    { 
        cipher c(3);
        CHECK_EQUAL("LAGODA", c.decrypt("GaaDlO")); 
    }

    TEST(EmptyString) 
    { 
        cipher c(3);
        CHECK_THROW(c.decrypt(""), cipher_error);
    }
    TEST(DigestText) 
    { 
        cipher c(3);
        CHECK_EQUAL("LAGODA", c.decrypt("GAADLO4342"));
    }
    TEST(PunctuationUndSpaceText) 
    { 
        cipher c(3);
        CHECK_EQUAL("LAGODA", c.decrypt("G A A D L,O"));
    }
    
    TEST(NonAsciiDecrypt){
        cipher c(3);
        CHECK_EQUAL("LAGODA",c.decrypt("GAADLOпрвет"));
    }
    TEST(SpaceTextBeginEndDecrypt){
        cipher c(3);
        CHECK_EQUAL("LAGODA",c.decrypt(" GA AD LO "));
    }
}

int main() {
    return UnitTest::RunAllTests();
}
