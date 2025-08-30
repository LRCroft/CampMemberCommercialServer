using CroftTeamsWinUITemplate.Models;
using ProtoBuf;

namespace campmember_commercial_webapp_linuximg.Models
{
    [ProtoContract]
    public class Model_CampPasswordManagerEnterprise_CachePublicKey
    {
        [ProtoMember(1)]
        public string connectionID { get; set; }

        [ProtoMember(2)]
        public List<Model_CampMember_NecessaryKey_ByteArray> listOfNecessaryKeys { get; set; }
    }
}