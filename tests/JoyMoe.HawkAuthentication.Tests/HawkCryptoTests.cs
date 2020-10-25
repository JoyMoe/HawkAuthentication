using Xunit;

namespace JoyMoe.HawkAuthentication.Tests
{
    public class HawkCryptoTests
    {
        private const string Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn";

        [Fact]
        public void RandomStringTests()
        {
            var nonce = HawkCrypto.RandomString();
            Assert.Equal(28, nonce.Length);
            Assert.NotEqual(HawkCrypto.RandomString(), nonce);
        }

        [Fact]
        public void  CalculateHmacTests()
        {
            var mac = HawkCrypto.CalculateHmac(Key, "foo");
            Assert.Equal("bzfOhM4KCX3te8w39YV5ctVtrAHpMW+2dtUBSM7wLhI=", mac);
        }

        [Fact]
        public void  CalculatePayloadHashTests()
        {
            var hash = HawkCrypto.CalculatePayloadHash("text/plain", "Thank you for flying Hawk");
            Assert.Equal("Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=", hash);
        }

        [Fact]
        public void  CalculateMacTests()
        {
            var mac = HawkCrypto.CalculateMac(Key, 1353832234, "j4h3g2", "GET", "/resource/1?b=1&a=2", "example.com", 8000, null, "some-app-ext-data");
            Assert.Equal("6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=", mac);
        }

        [Fact]
        public void  CalculateMacWithPayloadTests()
        {
            var hash = HawkCrypto.CalculatePayloadHash("text/plain", "Thank you for flying Hawk");
            Assert.Equal("Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=", hash);

            var mac = HawkCrypto.CalculateMac(Key, 1353832234, "j4h3g2", "POST", "/resource/1?b=1&a=2", "example.com", 8000, hash, "some-app-ext-data");
            Assert.Equal("aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw=", mac);
        }

        [Fact]
        public void CalculateTsMacTests()
        {
            var tsm = HawkCrypto.CalculateTsMac(Key, 1353832234);
            Assert.Equal("2mw1eh/qXzl0wJZ/E6XvBhRMEJN7L3j8AyMA8eItEb0=", tsm);
        }
    }
}
