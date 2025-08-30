using Azure;
using CroftTeamsWinUITemplate.Models;
using CroftTeamsWinUITemplate.Services.HotAgency;
using CroftTeamsWinUITemplate.Services.Machines;
using Oracle.ManagedDataAccess.Client;
using ProtoBuf;
using System.Data;
using System.Diagnostics;
using System.Text;

namespace campmember_commercial_webapp_linuximg.Services.HotAgency
{
    public class CampMember_Account_Manager_Agenc_Old
    {
        public bool CryptoServiceStatus = false;

        Configuration_CampPasswordManagerEnterprise_AccountRecovery_PINFromServer_Encrypted tempConfiguration_AccountRecovery_PINFromServer_Encrypted = new Configuration_CampPasswordManagerEnterprise_AccountRecovery_PINFromServer_Encrypted();

        CryptoService hotCryptoService;
        CampCommercialServer_Stripe_agency hotStripeAgency;


        CampCommercialServer_OracleObjectStorage_agency hotOracle_Object_Storage_Agency;

        Model_CampMember_ServiceContext tempModel_CampMemberServiceContext;

        public CampMember_Account_Manager_Agenc_Old(Model_CampMember_ServiceContext context)
        {
            tempModel_CampMemberServiceContext = context;


            hotOracle_Object_Storage_Agency = new CampCommercialServer_OracleObjectStorage_agency(context);


            tempModel_CampMemberServiceContext.ErrorMessage += "LLLL";

            hotStripeAgency = new CampCommercialServer_Stripe_agency(context);

            GetCryptoServiceReady();
        }

        private async Task GetCryptoServiceReady()
        {
            hotCryptoService = new CryptoService(tempModel_CampMemberServiceContext, 1, null, null, null);

            while (!hotCryptoService.CryptoServiceStatus)
            {
                await Task.Delay(50);
            }

            CryptoServiceStatus = true;
        }




        public async Task<Model_CampMember_AccountAgencyConsultResults> IfAccountCannotReceiveAService()
        {
            try
            {
                Model_CampMember_AccountAgencyConsultResults tempModel_AccountAgencyConsultResults = new Model_CampMember_AccountAgencyConsultResults();


                CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency hotBlob_Agency_CampMemberBlob = new CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency(tempModel_CampMemberServiceContext);

                Configuration_CampMember_Encrypted tempConfiguration_CampMember_Encrypted = await hotOracle_Object_Storage_Agency.CPMEUserConfigDownload();

                tempModel_AccountAgencyConsultResults.ActualUserConfigurationEncrypted = tempConfiguration_CampMember_Encrypted;

                if (UnicodeReaderMachine.ByteArrayToUnicodeAsync(await hotCryptoService.DecryptWithCommonAgency(tempModel_AccountAgencyConsultResults.ActualUserConfigurationEncrypted.AccountStatus)) == "LockedFromPINExceed")
                {
                    tempModel_AccountAgencyConsultResults.AccountLockedFromPINLocked = true;
                }
                else
                {
                    tempModel_AccountAgencyConsultResults.AccountLockedFromPINLocked = false;
                }

                if (UnicodeReaderMachine.ByteArrayToUnicodeAsync(await hotCryptoService.DecryptWithCommonAgency(tempModel_AccountAgencyConsultResults.ActualUserConfigurationEncrypted.LoginCPMKeyRequirement)) == "1")
                {
                    tempModel_AccountAgencyConsultResults.AccountRequiredKeyToAccessForAllOperation = true;
                }
                else
                {
                    tempModel_AccountAgencyConsultResults.AccountRequiredKeyToAccessForAllOperation = false;
                }

                tempModel_AccountAgencyConsultResults.IsActiveCampMember = hotStripeAgency.HasActiveSubscription();

                if (!tempModel_AccountAgencyConsultResults.IsActiveCampMember)
                {
                    // For Production
                    Configuration_CampStore_LifetimePurchase_ByteArray tempConfiguration_LifetimePurchase_ByteArray = await hotStripeAgency.IfLifetimePurchaseExistedThenGetFirstFoundedPurchaseDetails();
                    if (tempConfiguration_LifetimePurchase_ByteArray != null)
                    {
                        tempModel_AccountAgencyConsultResults.IsActiveCampMember = true;
                    }
                    else
                    {

                    }
                }

                tempModel_AccountAgencyConsultResults.UserDefinedSessionTime = ByteArrayAndConversionMachine.ConvertUnicodeBytesToInt32(await hotCryptoService.DecryptWithCommonAgency(tempModel_AccountAgencyConsultResults.ActualUserConfigurationEncrypted.SessionMinuteForHotLoginObject));

                return tempModel_AccountAgencyConsultResults;
            }
            catch (Exception ex)
            {
                tempModel_CampMemberServiceContext.ErrorMessage += $"CampMember_Account_Manager_Agency IfAccountCannotReceiveAService error : {ex.Message}";

                return null;
            }
        }




        public async Task<Model_CampPasswordManagerEnterprise_Read_Pin_From_Server> ResetAccountLockPINAttemptAndSetNewPIN(string newAccountstatus)
        {
            //Blob_Agency_CampMemberBlob hotBlob_Agency_CampMemberBlob = new Blob_Agency_CampMemberBlob(tempModel_CampMemberServiceContext);

            //Configuration_CampMember_Encrypted tempConfiguration_CampMember_Encrypted = await hotBlob_Agency_CampMemberBlob.CPMEUserConfigDownload();



            //byte[] tempNewAccountStatusEncrypted = await hotCryptoService.EncryptWithCommonAgency(UnicodeReaderMachine.ConvertUnicodeStringToByteArray("Default"));
            //byte[] tempPINAttemptedEncrypted = await hotCryptoService.EncryptWithCommonAgency(UnicodeReaderMachine.ConvertUnicodeStringToByteArray("0"));
            //byte[] newTempPin = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(GenerateRandom6DigitNumber().ToString());
            //byte[] tempPIN0ParamEncrypted = await hotCryptoService.EncryptWithCommonAgency(newTempPin);
            //DateTime tempCreateDateTime = DateTime.Now;
            //byte[] tempCreateDateTimeEncrypted = await hotCryptoService.EncryptWithCommonAgency(DateTimeConversionMachine.DateTimeToBytes(tempCreateDateTime));






            //CampMember_SQL_Agency hotCampMember_SQL_Agency = new CampMember_SQL_Agency(tempModel_CampMemberServiceContext);

            //await hotCampMember_SQL_Agency.CPME_ResetAccountWithNewRandomPIN();

            Model_CampPasswordManagerEnterprise_Read_Pin_From_Server PINReadFromServer = new Model_CampPasswordManagerEnterprise_Read_Pin_From_Server();

            return PINReadFromServer;
        }












        // BLOB NOW!
        public async Task ChangeAccountStatus(byte[] user_IdentifierSHA256, string accountStatus)
        {
            CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency hotBlob_Agency_CampMemberBlob = new CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency(tempModel_CampMemberServiceContext);

            await hotCryptoService.InitilizeCryptoservices(1, null,null,null);

            while(!CryptoServiceStatus)
            {
                await Task.Delay(50);
            }

            byte[] accountStatusEncrypted = await hotCryptoService.EncryptWithCommonAgency(UnicodeReaderMachine.ConvertUnicodeStringToByteArray(accountStatus));

            Configuration_CampMember_Encrypted tempConfiguration_CampMember_Encrypted = await hotOracle_Object_Storage_Agency.CPMEUserConfigDownload();

            tempConfiguration_CampMember_Encrypted.AccountStatus = accountStatusEncrypted;

            await hotOracle_Object_Storage_Agency.CPMEUserConfigOverwrite(tempConfiguration_CampMember_Encrypted);
        }

        static string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
            StringBuilder result = new StringBuilder(length);
            Random random = new Random();

            for (int i = 0; i < length; i++)
            {
                result.Append(chars[random.Next(chars.Length)]);
            }

            return result.ToString();
        }

        // This function is generate 6 digit random numbers
        public static int GenerateRandom6DigitNumber()
        {
            Random random = new Random();
            return random.Next(100000, 1000000);
        }
    }
}
