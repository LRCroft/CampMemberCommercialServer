using CroftTeamsWinUITemplate.Models;

namespace campmember_commercial_webapp_linuximg.Models
{
    public class Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicator
    {
        public bool isCacheStillConsistent { get; set; }

        public bool isFavoriteIndicated { get; set; }

        public Guid RecordsGUID { get; set; }

        public List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray> tempCacheMode0 { get; set; }

        public List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray> tempCacheMode1 { get; set; }

        public Model_CampPasswordManagerEnterprise_LandingPage_ByteArray tempNewCacheItem { get; set; }
    }
}