#include "modAlphaCipher.cpp"
#include "modAlphaCipher.h"

#include <UnitTest++/UnitTest++.h>
#include <locale>
using namespace std;
SUITE(KeyTest)
{
    TEST(ValidKey) { 
    wstring q1 = L"АЯЯКАМДС";
    wstring q2 = modAlphaCipher(L"АСЯ").encrypt(L"АНАКОНДА");
    if (q1==q2) {
    CHECK(true);
    }
    else {
    CHECK(false);
    }
    }
    TEST(LongKey) { 
    wstring q3 = L"ПСМ";
    wstring q4 = modAlphaCipher(L"ПАНДЕМОНИУМ").encrypt(L"АСЯ");
    if (q3==q4) {
    CHECK(true);
    }
    else {
    CHECK(false);
    }
    }
    TEST(LowCaseKey) { 
    wstring q5 = L"АЯЯКАМДС";
    wstring q6 = modAlphaCipher(L"ася").encrypt(L"АНАКОНДА");
    if (q5==q6) {
    CHECK(true);
    }
    else {
    CHECK(false);
    }
    }
    TEST(DigitsInKey) { CHECK_THROW(modAlphaCipher cp(L"Б1"), cipher_error); }
    TEST(PunctuationInKey) { CHECK_THROW(modAlphaCipher cp(L"Б,С"), cipher_error); }
    TEST(WhitespaceInKey) { CHECK_THROW(modAlphaCipher cp(L"Б С"), cipher_error); }
    TEST(EmptyKey) { CHECK_THROW(modAlphaCipher cp(L""), cipher_error); }
    TEST(WeakKey) { CHECK_THROW(modAlphaCipher cp(L"ААА"), cipher_error); }
}
struct KeyB_fixture {
    modAlphaCipher* p;
    KeyB_fixture() { p = new modAlphaCipher(L"Б"); }
    ~KeyB_fixture() { delete p; }
};
SUITE(EncryptTest)
{
 TEST_FIXTURE(KeyB_fixture, UpCaseString){
 wstring q7 = L"ТУБМЭДСПИЙУЦПМПЕОПКТНЁСУЭЯОБНОЁРСЙГЬЛБУЭСБКНБОЙУРСЁЛСБТОПКУСЁМЭЯФЗОЁЕПМДПЗЕБУЭ";
 wstring q8 = p->encrypt(L"СТАЛЬГРОЗИТХОЛОДНОЙСМЕРТЬЮНАМНЕПРИВЫКАТЬРАЙМАНИТПРЕКРАСНОЙТРЕЛЬЮУЖНЕДОЛГОЖДАТЬ");
 if (q7==q8) {
 CHECK(true);
 }
 else {
 CHECK(false);
 } 
 }
 TEST_FIXTURE(KeyB_fixture, LowCaseString){
 wstring q9 = L"ТУБМЭДСПИЙУЦПМПЕОПКТНЁСУЭЯОБНОЁРСЙГЬЛБУЭСБКНБОЙУРСЁЛСБТОПКУСЁМЭЯФЗОЁЕПМДПЗЕБУЭ";
 wstring q10 = p->encrypt(L"стальгрозитхолоднойсмертьюнамнепривыкатьрайманитпрекраснойтрельюужнедолгождать");
 if (q9==q10) {
 CHECK(true);
 }
 else {
 CHECK(false);
 } 
 }
 TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct){
 wstring q11 = L"ТУБМЭДСПИЙУЦПМПЕОПКТНЁСУЭЯОБНОЁРСЙГЬЛБУЭСБКНБОЙУРСЁЛСБТОПКУСЁМЭЯФЗОЁЕПМДПЗЕБУЭ";
 wstring q12 = p->encrypt(L"СТАЛЬ ГРОЗИТ ХОЛОДНОЙ СМЕРТЬЮ, НАМ НЕ ПРИВЫКАТЬ, РАЙ МАНИТ ПРЕКРАСНОЙ ТРЕЛЬЮ , УЖ НЕ ДОЛГО ЖДАТЬ");
 if (q11==q12) {
 CHECK(true);
 }
 else {
 CHECK(false);
 }
 }
 TEST_FIXTURE(KeyB_fixture, StringWithNumbers){
 wstring q13 = L"ТОПГЬНДПЕПН";
 wstring q14 = p->encrypt(L"Сновым2024годом");
 if (q13==q14) {
 CHECK(true);
 }
 else {
 CHECK(false);
 }
 }
 TEST_FIXTURE(KeyB_fixture, EmptyString) {
 CHECK_THROW(p->encrypt(L""),cipher_error);
 }
 TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
 CHECK_THROW(p->encrypt(L"1234+8765=9999"),cipher_error);
 }
 TEST(MaxShiftKey){
 wstring q15 = L"РСЯКЫВПНЖЗСФНКНГМНИРЛДПСЫЭМЯЛМДОПЗБЪЙЯСЫПЯИЛЯМЗСОПДЙПЯРМНИСПДКЫЭТЁМДГНКВНЁГЯСЫ";
 wstring q16 = modAlphaCipher(L"Я").encrypt(L"СТАЛЬГРОЗИТХОЛОДНОЙСМЕРТЬЮНАМНЕПРИВЫКАТЬРАЙМАНИТПРЕКРАСНОЙТРЕЛЬЮУЖНЕДОЛГОЖДАТЬ");
 if (q15==q16) {
 CHECK(true);
 }
 else {
 CHECK(false);
 } 
 }
}
 
SUITE(DecryptText)
{
 TEST_FIXTURE(KeyB_fixture, UpCaseString) {
 wstring q17 = L"СТАЛЬГРОЗИТХОЛОДНОЙСМЕРТЬЮНАМНЕПРИВЫКАТЬРАЙМАНИТПРЕКРАСНОЙТРЕЛЬЮУЖНЕДОЛГОЖДАТЬ";
 wstring q18 = p->decrypt(L"ТУБМЭДСПИЙУЦПМПЕОПКТНЁСУЭЯОБНОЁРСЙГЬЛБУЭСБКНБОЙУРСЁЛСБТОПКУСЁМЭЯФЗОЁЕПМДПЗЕБУЭ");
 if (q17==q18) {
 CHECK(true);
 }
 else {
 CHECK(false);
 }
 } 
 TEST_FIXTURE(KeyB_fixture, LowCaseString) {
 CHECK_THROW(p->decrypt(L"фывЫФВЫФЧФЫЫФВЫФСЧЯСЧЯМЧЯМ"),cipher_error);
 }
 TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
 CHECK_THROW(p->decrypt(L"ФЫВ ЫФВ ЫФЧФ ЫФВ ЫФСЧ ЯСЧЯМЧ ЯМ"),cipher_error);
 }
 TEST_FIXTURE(KeyB_fixture, DigitsString) {
 CHECK_THROW(p->decrypt(L"ФЫВЫФВЫФЧ123445ФЫЫФВЫФСЧЯСЧЯМЧЯМ"),cipher_error);
 }
 TEST_FIXTURE(KeyB_fixture, PunctString) {
 CHECK_THROW(p->decrypt(L"ФЫВЫФВЫФЧ,ЫЫФВЫФСЧЯСЧЯМЧЯМ"),cipher_error);
 }
 TEST_FIXTURE(KeyB_fixture, EmptyString) {
 CHECK_THROW(p->decrypt(L""),cipher_error);
 }
 TEST(MaxShiftKey) {
 wstring q19 = L"СТАЛЬГРОЗИТХОЛОДНОЙСМЕРТЬЮНАМНЕПРИВЫКАТЬРАЙМАНИТПРЕКРАСНОЙТРЕЛЬЮУЖНЕДОЛГОЖДАТЬ";
 wstring q20 = modAlphaCipher(L"Я").decrypt(L"РСЯКЫВПНЖЗСФНКНГМНИРЛДПСЫЭМЯЛМДОПЗБЪЙЯСЫПЯИЛЯМЗСОПДЙПЯРМНИСПДКЫЭТЁМДГНКВНЁГЯСЫ");
 if (q19==q20) {
 CHECK(true);
 }
 else {
 CHECK(false);
 }
 }

}
int main(int argc, char** argv) {
	std::locale loc("ru_RU.UTF-8");
    std::locale::global(loc);
	return UnitTest::RunAllTests(); }

