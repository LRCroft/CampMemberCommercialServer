using CroftTeamsWinUITemplate.Models;

namespace campmember_commercial_webapp_linuximg.Models
{
    public class Main_Cache_CampPasswordManagerEnterprise
    {
        public CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray CampMember_Configuration_Filtered_ByteArrayx { get; set; }

        public Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResult Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx { get; set; }

        public Model_CampPasswordManagerEnterprise_RecordsID_TryDecryptResult Model_CampPasswordManagerEnterprise_RecordsID_TryDecryptResultx { get; set; }

        public List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray> ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All { get; set; }

        public List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray> ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite { get; set; }

        public List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray> ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Recycle { get; set; }

        public Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicator Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx { get; set; }

        public bool isMoveRecordsToBinAFavorited { get; set; }

        public bool isUpdateRecordsAFavorited { get; set; }

        public bool isRecoverRecordsAFavorited { get; set; }

        public bool isCopyPasswordAFavorited { get; set; }
    }
}