using FluentAssertions;
using Xunit;

namespace HawkAuthentication.Tests
{
    public class HawkCryptoTests
    {
        private const string Key = "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn";

        [Fact]
        public void RandomStringTests()
        {
            var nonce = HawkCrypto.RandomString();
            nonce.Length.Should().BeGreaterOrEqualTo(28);
            nonce.Should().NotBeSameAs(HawkCrypto.RandomString());
        }

        [Fact]
        public void  CalculateHmacTests()
        {
            var mac = HawkCrypto.CalculateHmac(Key, "foo");
            mac.Should().BeEquivalentTo("bzfOhM4KCX3te8w39YV5ctVtrAHpMW+2dtUBSM7wLhI=");
        }

        [Fact]
        public void  CalculatePayloadHashTests()
        {
            var hash = HawkCrypto.CalculatePayloadHash("text/plain", "Thank you for flying Hawk");
            hash.Should().BeEquivalentTo("Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=");
        }

        [Fact]
        public void  CalculateMacTests()
        {
            var mac = HawkCrypto.CalculateMac(Key, 1353832234, "j4h3g2", "GET", "/resource/1?b=1&a=2", "example.com", 8000, null, "some-app-ext-data");
            mac.Should().BeEquivalentTo("6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=");
        }

        [Fact]
        public void  CalculateMacWithPayloadTests()
        {
            var hash = HawkCrypto.CalculatePayloadHash("text/plain", "Thank you for flying Hawk");
            hash.Should().BeEquivalentTo("Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=");

            var mac = HawkCrypto.CalculateMac(Key, 1353832234, "j4h3g2", "POST", "/resource/1?b=1&a=2", "example.com", 8000, hash, "some-app-ext-data");
            mac.Should().BeEquivalentTo("aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw=");
        }

        [Fact]
        public void CalculateTsMacTests()
        {
            var tsm = HawkCrypto.CalculateTsMac(Key, 1353832234);
            tsm.Should().BeEquivalentTo("2mw1eh/qXzl0wJZ/E6XvBhRMEJN7L3j8AyMA8eItEb0=");
        }
    }
}
