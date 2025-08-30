using Azure;
using campmember_commercial_webapp_linuximg.Models;
using CroftTeamsWinUITemplate.Models;
using CroftTeamsWinUITemplate.Services.HotAgency;
using CroftTeamsWinUITemplate.Services.Machines;
using Mono.Unix.Native;
using Oracle.ManagedDataAccess.Client;
using ProtoBuf;
using System.ComponentModel;
using System.Configuration.Provider;
using System.Data;
using System.Diagnostics;
using System.Text;
using static Google.Apis.Requests.BatchRequest;

namespace campmember_commercial_webapp_linuximg.Services
{
    public class Camp_Password_Manager_Enterprise_Service
    {
        Model_CampMember_ServiceContext tempModel_CampMember_ServiceContext;
        Main_CampPasswordManagerEnterprise_Request_FromClient tempMain_CPME_Request_FromClient;
        Configuration_CampPasswordManagerEnterprise_ClientRequestResults tempConfiguration_CPME_ClientRequestResults;
        Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise;

        CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency;
        CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency;
        CampCommercialServer_OracleObjectStorage_agency hotOracle_Object_Storage_Agency;


        public Camp_Password_Manager_Enterprise_Service(Model_CampMember_ServiceContext context, Main_CampPasswordManagerEnterprise_Request_FromClient data)
        {
            tempModel_CampMember_ServiceContext = context;
            tempMain_CPME_Request_FromClient = data;

            tempConfiguration_CPME_ClientRequestResults = new Configuration_CampPasswordManagerEnterprise_ClientRequestResults
            {
                Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult()
                {

                },

                Main_DataModel_FromServerx = new Main_CampPasswordManagerEnterprise_DataModel_FromServer()
                {

                },

                JobID = data.JobID
            };

            tempMain_Cache_CampPasswordManagerEnterprise = new Main_Cache_CampPasswordManagerEnterprise()
            {
                CampMember_Configuration_Filtered_ByteArrayx = new CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray()
                {

                },

                Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx = new Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResult()
                {

                },

                Model_CampPasswordManagerEnterprise_RecordsID_TryDecryptResultx = new Model_CampPasswordManagerEnterprise_RecordsID_TryDecryptResult()
                {

                },

                ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All = new List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray>()
                {

                },

                ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite = new List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray>()
                {

                },

                ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Recycle = new List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray>()
                {

                },

                Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx = new Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicator()
                {

                }
            };

            hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency = new CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency(context);
            hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency = new CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency(context);
            hotOracle_Object_Storage_Agency = new CampCommercialServer_OracleObjectStorage_agency(context);
        }

        public async Task<(byte[], Main_Cache_CampPasswordManagerEnterprise?)> RunService()
        {


            try
            {
                var MainSW = Stopwatch.StartNew();

                CampCommercialServer_Account_Manager_agency hotCampMember_Account_Manager_Agency = new CampCommercialServer_Account_Manager_agency(tempModel_CampMember_ServiceContext);
                while (!hotCampMember_Account_Manager_Agency.CryptoServiceStatus)
                {
                    await Task.Delay(50);
                }

                tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx = await hotCampMember_Account_Manager_Agency.IfAccountCannotReceiveAService();









                //// Check if have PIN locked
                if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.AccountLockedFromPINLocked)
                {
                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Check account readiness");

                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.HotAccountStatus = UnicodeReaderMachine.ConvertUnicodeStringToByteArray("911");
                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);

                    //// If User request for PIN Recovery Object
                    if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_RequestForPINRecoveryThroughEmailx != null)
                    {

                        CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_RequestForPINRecoveryThroughEmailx);
                        while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                        {
                            await Task.Delay(10);
                        }

                        await hotCPMAccessKeyAgency.RequestNewKeyOrPINRecoveryAndSendThroughEmail(tempModel_CampMember_ServiceContext.HttpRequestx);

                        if (hotCPMAccessKeyAgency.isEmailServiceRunSuccessfully)
                        {
                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                        }
                        else
                        {
                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                        }
                    }




                    //// If User send recovery object for unlock an account
                    else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_SendPINRecoveryObjectForRecoverAccountx != null)
                    {
                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Recovering account");

                        CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINRecoveryFromClient_Encryptedx);
                        while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                        {
                            await Task.Delay(10);
                        }

                        await hotCPMAccessKeyAgency.GetServerKeySet();
                        await hotCPMAccessKeyAgency.StartComparisonDateTimIfOverAnyMinutes(50);

                        if (hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults.IsOverAvailableTime)
                        {
                        }
                        else
                        {
                            await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();

                            if (hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults.ComparisonResult == true)
                            {
                                CryptoService hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 1, null, null, null);


                                while (!hotCampMember_Account_Manager_Agency.CryptoServiceStatus)
                                {
                                    await Task.Delay(10);
                                }

                                Model_CampPasswordManagerEnterprise_Read_Pin_From_Server tempModel_Read_Pin_From_Server = await hotCampMember_Account_Manager_Agency.ResetAccountLockPINAttemptAndSetNewPIN("Default");
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.HotAccountStatus = UnicodeReaderMachine.ConvertUnicodeStringToByteArray("0");
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);


                                while (!hotCryptoService.CryptoServiceStatus)
                                {
                                    await Task.Delay(10);
                                }
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.NewPIN = await hotCryptoService.DecryptWithCommonAgency(tempModel_Read_Pin_From_Server.EncryptedPin);
                            }
                            else
                            {
                            }
                        }
                    }
                    else
                    {
                        // Account has 'No PIN locked'
                    }
                }
                else
                {
                    //// Check if user need Key access for all operation or not
                    bool isAnotherServicesIsRequired = false;
                    if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.AccountRequiredKeyToAccessForAllOperation)
                    {
                        //// If user need us to send a key through email
                        if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_RequestForHotKeyAccessThroughEmailx != null)
                        {
                            CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_RequestForHotKeyAccessThroughEmailx);

                            while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                await Task.Delay(10);

                            await hotCPMAccessKeyAgency.RequestNewKeyOrPINRecoveryAndSendThroughEmail(tempModel_CampMember_ServiceContext.HttpRequestx);

                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                ByteArrayAndConversionMachine.ConvertBoolToByteArray(hotCPMAccessKeyAgency.isEmailServiceRunSuccessfully);

                            isAnotherServicesIsRequired = false;
                        }
                        //// If user send key for just login with a key
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_LoginwithKeyx != null)
                        {
                            var hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_KeyFromClient_Encryptedx);

                            while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                await Task.Delay(10);

                            await hotCPMAccessKeyAgency.GetServerKeySet();

                            try
                            {
                                await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();

                                if (hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults.ComparisonResult == true)
                                {
                                    await hotCPMAccessKeyAgency.StartComparisonDateTimIfOverAnyMinutes(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.UserDefinedSessionTime);

                                    if (hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults.IsOverAvailableTime)
                                    {
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.KeyAccessIsExpired = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    }
                                    else
                                    {
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.HotAccountStatus = UnicodeReaderMachine.ConvertUnicodeStringToByteArray("KeyValid");
                                        // Provide a services here
                                    }
                                }
                                else
                                {
                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                }
                            }
                            catch
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.NotAKeyAccess = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                            }
                            isAnotherServicesIsRequired = false;
                        }

                        else
                        {
                            CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_KeyFromClient_Encryptedx);

                            while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                await Task.Delay(10);

                            await hotCPMAccessKeyAgency.GetServerKeySet();

                            try
                            {
                                await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();

                                if (hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults.ComparisonResult == true)
                                {
                                    await hotCPMAccessKeyAgency.StartComparisonDateTimIfOverAnyMinutes(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.UserDefinedSessionTime);

                                    if (hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults.IsOverAvailableTime)
                                    {
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.KeyAccessIsExpired = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        isAnotherServicesIsRequired = false;
                                    }
                                    else
                                    {
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        // Provide a services here
                                        isAnotherServicesIsRequired = true;
                                    }
                                }
                                else
                                {
                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    isAnotherServicesIsRequired = false;
                                }
                            }
                            catch (Exception ex)
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += $"Verify key for access a services : {ex.Message}";
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.NotAKeyAccess = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                isAnotherServicesIsRequired = false;
                            }
                        }

                    }
                    else
                    {
                        // No require any of Key Verification
                        isAnotherServicesIsRequired = true;
                    }




                    // Provide Another services
                    if (isAnotherServicesIsRequired)
                    {
                        CryptoService hotCryptoServiceWithKeyOrder1 = new CryptoService(tempModel_CampMember_ServiceContext, 1, null, null, null);


                        // GPT Checked 1
                        //// Login with PIN
                        if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_LoginwithPINx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Logging in with PIN");

                            while (!hotCryptoServiceWithKeyOrder1.CryptoServiceStatus)
                                await Task.Delay(10);

                            string decryptedPinRequirement = null;

                            if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray != null)
                            {
                                decryptedPinRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray.LoginPINRequirement);
                            }
                            else
                            {
                                decryptedPinRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(
                                    await hotCryptoServiceWithKeyOrder1.DecryptWithCommonAgency(
                                        tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.ActualUserConfigurationEncrypted.LoginPINRequirement
                                    )
                                );
                            }

                            if (decryptedPinRequirement == "1") // PIN required
                            {
                                if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                                {
                                    var hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);

                                    await hotCPMAccessKeyAgency.GetServerKeySet();
                                    await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();

                                    var tempConfiguration_AccessServiceResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                    if (tempConfiguration_AccessServiceResults.ComparisonResult == true)
                                    {
                                        await hotCPMAccessKeyAgency.ResetPINAttempted();
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                    }
                                    else
                                    {
                                        await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    }
                                }
                                else
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                }
                            }
                            else
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += "No require any verification";
                            }
                        }



                        // GPT Checked 1
                        //// Very much Completed
                        //// Open setting panel
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_OpenSettingsPanelx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Openning settings configuration");

                            if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                            {
                                try
                                {
                                    CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Validating PIN");

                                    await hotCPMAccessKeyAgency.GetServerKeySet();
                                    await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();

                                    var tempConfiguration_AccessServiceResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                    if (tempConfiguration_AccessServiceResults.ComparisonResult == true)
                                    {
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                    }
                                    else
                                    {
                                        await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    }
                                }
                                catch (Exception ex)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                }
                            }
                            else
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                            }
                        }


                        // GPT Checked 1
                        // Completed
                        // Hot Favorite
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_MakeHotFavoritex != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Making records as favorite");

                            bool isEligibleAfterAssessment = false;



                            string MakeHotFavoritePINRequirement = null;

                            if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray != null)
                            {
                                MakeHotFavoritePINRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray.MakeHotFavoritePINRequirement);
                            }
                            else
                            {
                                MakeHotFavoritePINRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(await hotCryptoServiceWithKeyOrder1.DecryptWithCommonAgency(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.ActualUserConfigurationEncrypted.MakeHotFavoritePINRequirement));
                            }


                            if (MakeHotFavoritePINRequirement == "1")
                            {
                                if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                                {
                                    try
                                    {
                                        var hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);

                                        await hotCPMAccessKeyAgency.GetServerKeySet();

                                        while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                            await Task.Delay(10);

                                        await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();

                                        var tempConfiguration_AccessServiceResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                        if (tempConfiguration_AccessServiceResults.ComparisonResult == true)
                                        {
                                            await hotCPMAccessKeyAgency.ResetPINAttempted();
                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                            isEligibleAfterAssessment = true;
                                        }
                                        else
                                        {
                                            await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                            isEligibleAfterAssessment = false;
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                else
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                isEligibleAfterAssessment = true;
                            }

                            if (isEligibleAfterAssessment)
                            {
                                if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_MakeHotFavoritex.PersonalKey != null)
                                {
                                    var hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, null, tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_MakeHotFavoritex.PersonalKey, null, null);

                                    while (!hotCryptoService.CryptoServiceStatus)
                                    {
                                        if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.PersonalKeyMightNotBeAKey == true)
                                            break;

                                        await Task.Delay(10);
                                    }

                                    try
                                    {
                                        await hotCryptoService.DecryptWithSpecialAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_MakeHotFavoritex.FavoriteIndicator);

                                        Model_CampPasswordManagerEnterprise_Records tempModel_CPME_Records = await hotOracle_Object_Storage_Agency.CPMERecordsDownload();

                                        var recordsID0 = UnicodeReaderMachine.ConvertByteArrayToGuid(
                                            await hotCryptoService.DecryptWithSpecialAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_MakeHotFavoritex.UniqueIdentifier)
                                        );

                                        var targetRecord = tempModel_CPME_Records?.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx?.FirstOrDefault(x => x.UniqueIdentifier == recordsID0);

                                        if (targetRecord != null)
                                        {
                                            targetRecord.FavoriteIndicator = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_MakeHotFavoritex.FavoriteIndicator;
                                            await hotOracle_Object_Storage_Agency.CPMERecordsOverwrite(tempModel_CPME_Records);
                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        }
                                        else
                                        {
                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        }
                                    }
                                    catch
                                    {
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    }
                                }
                                else
                                {
                                    var hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 2, null, null, null);

                                    while (!hotCryptoService.CryptoServiceStatus)
                                        await Task.Delay(10);

                                    if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.PersonalKeyMightNotBeAKey == true)
                                    {
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.NotAKeyAccess = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    }
                                    else
                                    {
                                        try
                                        {
                                            await hotCryptoService.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_MakeHotFavoritex.FavoriteIndicator);

                                            var tempModel_CPME_Records = await hotOracle_Object_Storage_Agency.CPMERecordsDownload();

                                            var recordsID0 = UnicodeReaderMachine.ConvertByteArrayToGuid(
                                                await hotCryptoService.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_MakeHotFavoritex.UniqueIdentifier)
                                            );

                                            var targetRecord = tempModel_CPME_Records?.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx?.FirstOrDefault(x => x.UniqueIdentifier == recordsID0);

                                            if (targetRecord != null)
                                            {
                                                targetRecord.FavoriteIndicator = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_MakeHotFavoritex.FavoriteIndicator;
                                                await hotOracle_Object_Storage_Agency.CPMERecordsOverwrite(tempModel_CPME_Records);
                                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                            }
                                            else
                                            {
                                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                            }
                                        }
                                        catch
                                        {
                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        }
                                    }
                                }
                            }
                            else
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }

                        // GPT Checked 1
                        //// Completed
                        //// Create new records
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Creating new records");

                            tempModel_CampMember_ServiceContext.ErrorMessage += $"INTO";

                            bool isEligibleAfterAssessment = false;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Server crypto initializing");

                            while (!hotCryptoServiceWithKeyOrder1.CryptoServiceStatus)
                                await Task.Delay(50);

                            tempModel_CampMember_ServiceContext.ErrorMessage += $"1";










                            string CreateNewRecordsPINRequirement = null;

                            if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray != null)
                            {
                                CreateNewRecordsPINRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray.CreateNewRecordsPINRequirement);
                            }
                            else
                            {
                                CreateNewRecordsPINRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(await hotCryptoServiceWithKeyOrder1.DecryptWithCommonAgency(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.ActualUserConfigurationEncrypted.CreateNewRecordsPINRequirement));
                            }


                            bool pinRequired;

                            if (CreateNewRecordsPINRequirement == "1")
                            {
                                pinRequired = true;
                            }
                            else
                            {
                                pinRequired = false;
                            }






                            tempModel_CampMember_ServiceContext.ErrorMessage += $"2";

                            Task pinCheckTask = Task.CompletedTask;

                            tempModel_CampMember_ServiceContext.ErrorMessage += $"3";

                            Task<Model_CampPasswordManagerEnterprise_Records?> blobDownloadTask = hotOracle_Object_Storage_Agency.CPMERecordsDownload();

                            tempModel_CampMember_ServiceContext.ErrorMessage += $"4";

                            if (pinRequired)
                            {

                                tempModel_CampMember_ServiceContext.ErrorMessage += $"5";

                                if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                                {

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"6";

                                    pinCheckTask = Task.Run(async () =>
                                    {
                                        try
                                        {
                                            tempModel_CampMember_ServiceContext.ErrorMessage += $"7";

                                            CampCommercialServer_AccessKey_agency hotAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext,
                                                tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);

                                            tempModel_CampMember_ServiceContext.ErrorMessage += $"8";

                                            while (!hotAccessKeyAgency.CryptoServiceStatus)
                                                await Task.Delay(50);


                                            tempModel_CampMember_ServiceContext.ErrorMessage += $"9";

                                            await hotAccessKeyAgency.GetServerKeySet();
                                            await hotAccessKeyAgency.StartComparisonIfKeyIsMatched();

                                            tempModel_CampMember_ServiceContext.ErrorMessage += $"10";

                                            if (hotAccessKeyAgency.tempConfiguration_ServiceAccessResults.ComparisonResult == true)
                                            {
                                                tempModel_CampMember_ServiceContext.ErrorMessage += $"11";

                                                await hotAccessKeyAgency.ResetPINAttempted();
                                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                                    ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                                isEligibleAfterAssessment = true;

                                                tempModel_CampMember_ServiceContext.ErrorMessage += $"12";
                                            }
                                            else
                                            {
                                                tempModel_CampMember_ServiceContext.ErrorMessage += $"13";

                                                await hotAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                                    ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                                isEligibleAfterAssessment = false;

                                                tempModel_CampMember_ServiceContext.ErrorMessage += $"14";
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            tempModel_CampMember_ServiceContext.ErrorMessage += $"15";

                                            tempModel_CampMember_ServiceContext.ErrorMessage += $"Access check error: {ex.Message}";
                                            isEligibleAfterAssessment = false;
                                        }
                                    });
                                }
                                else
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += "PIN missing; provide key or contact support";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                isEligibleAfterAssessment = true;
                            }

                            await Task.WhenAll(pinCheckTask, blobDownloadTask);

                            tempModel_CampMember_ServiceContext.ErrorMessage += $"7777";

                            Model_CampPasswordManagerEnterprise_Records? tempModel_CPME_Records = blobDownloadTask.Result;

                            // Eligibility checks, update flag but no return
                            if (isEligibleAfterAssessment)
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += $"AAAA";

                                if (!tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.IsActiveCampMember)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"BBBB";

                                    if (tempModel_CPME_Records != null && tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx != null &&
                                        tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx.Count() >= 50)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"CCCC";

                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.RecordsReachedLimit = 1;
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                            ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        isEligibleAfterAssessment = false;

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"DDDD";
                                    }
                                }
                                else if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.IsActiveCampMember)
                                {

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"EEEE";

                                    if (tempModel_CPME_Records == null)
                                    {

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"FFFF";

                                        tempModel_CPME_Records = new Model_CampPasswordManagerEnterprise_Records()
                                        {
                                            ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx = new List<Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID>()
                                        };

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"GGGG";

                                    }
                                    isEligibleAfterAssessment = true;
                                }
                                else
                                {
                                    isEligibleAfterAssessment = false;
                                }
                            }

                            if (isEligibleAfterAssessment)
                            {
                                try
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"HHHH";

                                    Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID newRecord = new Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID();

                                    CryptoService hotCryptoService;

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"IIII";

                                    if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.PersonalKeyThatWishToUse == null)
                                    {

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"JJJJ";

                                        hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 2, null, null, null);
                                    }
                                    else
                                    {

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"KKKK";

                                        hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 2, tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.PersonalKeyThatWishToUse, null, null);
                                    }

                                    while (!hotCryptoService.CryptoServiceStatus)
                                        await Task.Delay(50);

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Check genuinity of data");

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"LLLL";












                                    // Start all decrypt tasks
                                    var favoriteTask = hotCryptoService.DecryptWithCommonAgency(
                                        tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.FavoriteIndicator);

                                    var specialKeyTask = hotCryptoService.DecryptWithCommonAgency(
                                        tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.SpecialKeyIndicator);

                                    var providerNameTask = hotCryptoService.DecryptWithCommonAgency(
                                        tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.ProviderName);

                                    var accountNameTask = hotCryptoService.DecryptWithCommonAgency(
                                        tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.AccountName);

                                    var revealCounterTask = hotCryptoService.DecryptWithCommonAgency(
                                        tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.RevealingCounterForAccountName);

                                    var providerUrlTask = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.PersonalKeyThatWishToUse == null
                                        ? hotCryptoService.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.ProviderURL)
                                        : hotCryptoService.DecryptWithSpecialAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.ProviderURL);

                                    var passwordTask = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.PersonalKeyThatWishToUse == null
                                        ? hotCryptoService.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.Password)
                                        : hotCryptoService.DecryptWithSpecialAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.Password);

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"MMMM";

                                    // Wait all
                                    await Task.WhenAll(
                                        favoriteTask, specialKeyTask, providerNameTask,
                                        accountNameTask, revealCounterTask, providerUrlTask, passwordTask);

                                    // Build new landing page item from decrypted data
                                    Model_CampPasswordManagerEnterprise_LandingPage_ByteArray newTempCacheItem = new Model_CampPasswordManagerEnterprise_LandingPage_ByteArray
                                    {
                                        FavoriteIndicator = await favoriteTask,
                                        SpecialKeyIndicator = await specialKeyTask,
                                        ProviderName = await providerNameTask,
                                        AccountName = await accountNameTask,
                                        RevealingCounterForAccountName = await revealCounterTask,
                                    };





                                    // Now you have validated (since decryption succeeded) 
                                    // and also fully filled your model item.


























                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Encrypting records");

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"NNNN";

                                    DateTime now = DateTime.Now;

                                    if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.PersonalKeyThatWishToUse == null)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"OOOO";

                                        newRecord.CreatedDate = await hotCryptoService.EncryptWithCommonAgency(DateTimeConversionMachine.DateTimeToBytes(now));
                                        newRecord.UpdatedDate = await hotCryptoService.EncryptWithCommonAgency(Encoding.Unicode.GetBytes(""));
                                        newRecord.LastPasswordCall = await hotCryptoService.EncryptWithCommonAgency(Encoding.Unicode.GetBytes(""));

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"PPPP";
                                    }
                                    else
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"QQQQ";

                                        newRecord.CreatedDate = await hotCryptoService.EncryptWithSpecialAgency(DateTimeConversionMachine.DateTimeToBytes(now));
                                        newRecord.UpdatedDate = await hotCryptoService.EncryptWithSpecialAgency(Encoding.Unicode.GetBytes(""));
                                        newRecord.LastPasswordCall = await hotCryptoService.EncryptWithSpecialAgency(Encoding.Unicode.GetBytes(""));

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"RRRR";
                                    }

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"SSSS";

                                    newRecord.UniqueIdentifier = Guid.NewGuid();
                                    newRecord.FavoriteIndicator = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.FavoriteIndicator;
                                    newRecord.ProviderName = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.ProviderName;
                                    newRecord.ProviderURL = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.ProviderURL;
                                    newRecord.AccountName = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.AccountName;
                                    newRecord.RevealingCounterForAccountName = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.RevealingCounterForAccountName;
                                    newRecord.EncryptedPassword = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.Password;
                                    newRecord.SpecialKeyIndicator = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CreateNewRecordsx.SpecialKeyIndicator;

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"TTTT";

                                    if (tempModel_CPME_Records == null || tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx == null)
                                    {
                                        tempModel_CPME_Records = new Model_CampPasswordManagerEnterprise_Records()
                                        {
                                            ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx = new List<Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID>()
                                        };
                                    }


                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Saving records");

















                                    // Check how cache will be updated


                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "1111");



                                    string favoriteIndicatorString = UnicodeReaderMachine.ByteArrayToUnicodeAsync(await favoriteTask);

                                    bool favoriteIndicator = false;

                                    if (favoriteIndicatorString == "1")
                                    {
                                        favoriteIndicator = true;
                                    }



                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "2222");












                                    int activeRecordsCount = tempModel_CPME_Records?.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx?.Count(r => r.DeletionCall == null) ?? 0;

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, $"Active recors count : {activeRecordsCount}");


                                    int favoriteRecordsCount = await hotCryptoService.CountFavoriteRecords(tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx);


                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, $"Favorite recors count : {favoriteRecordsCount}");




                                    bool isCacheMode0StillConsistence = false;

                                    bool isCacheMode1StillConsistence = false;




                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "111111");


                                    List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray> tempModel_CampPasswordManagerEnterprise_LandingPage_ByteArray0 = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewAllCacheDownload();


                                    int cacheactiveRecordsCount;

                                    if(tempModel_CampPasswordManagerEnterprise_LandingPage_ByteArray0 == null)
                                    {
                                        cacheactiveRecordsCount = 0;
                                    }
                                    else
                                    {
                                        cacheactiveRecordsCount = tempModel_CampPasswordManagerEnterprise_LandingPage_ByteArray0.Count();
                                    }

                                     





                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "222222");


                                    List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray> tempModel_CampPasswordManagerEnterprise_LandingPage_ByteArray1 = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewFavoriteCacheDownload();

                                    int cachefavoriteRecordsCount;

                                    if (tempModel_CampPasswordManagerEnterprise_LandingPage_ByteArray0 == null)
                                    {
                                        cachefavoriteRecordsCount = 0;
                                    }
                                    else
                                    {
                                        cachefavoriteRecordsCount = tempModel_CampPasswordManagerEnterprise_LandingPage_ByteArray0.Count();
                                    }


                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, $"Cache Active recors count : {cacheactiveRecordsCount}");

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, $"Cache Favorite recors count : {cachefavoriteRecordsCount}");









                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "3333333");


                                    if (activeRecordsCount == cacheactiveRecordsCount)
                                    {
                                        isCacheMode0StillConsistence = true;

                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Active records matched cache");
                                    }
                                    else
                                    {
                                        isCacheMode0StillConsistence = false;

                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Active records NOT matched cache");
                                    }

                                    if (favoriteRecordsCount == cachefavoriteRecordsCount)
                                    {
                                        isCacheMode1StillConsistence = true;

                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fav records matched cache");
                                    }
                                    else
                                    {
                                        isCacheMode0StillConsistence = false;

                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fav records NOT matched cache");
                                    }






                                    if (isCacheMode0StillConsistence == true && isCacheMode1StillConsistence == true)
                                    {
                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, $"AAAA");

                                        tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.isCacheStillConsistent = true;

                                        tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.tempCacheMode0 = tempModel_CampPasswordManagerEnterprise_LandingPage_ByteArray0;

                                        tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.tempCacheMode1 = tempModel_CampPasswordManagerEnterprise_LandingPage_ByteArray1;

                                        tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.tempNewCacheItem = newTempCacheItem;



                                        tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.isFavoriteIndicated = favoriteIndicator;

                                        tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.RecordsGUID = newRecord.UniqueIdentifier;

                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, $"BBBB");
                                    }
                                    else
                                    {
                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, $"CCCC");

                                        tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.isCacheStillConsistent = false;

                                        tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.isFavoriteIndicated = favoriteIndicator;

                                        await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewAllCacheDelete();

                                        await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewFavoriteCacheDelete();

                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, $"DDDD");
                                    }













                                    tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.tempNewCacheItem = newTempCacheItem;




                                    // Commit the records

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"UUUU";

                                    tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx.Add(newRecord);

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"VVVV";

                                    await hotOracle_Object_Storage_Agency.CPMERecordsOverwrite(tempModel_CPME_Records);

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"WWWWW";






                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "overwrite");

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"XXXX";
                                }
                                catch (Exception ex)
                                {

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, $"Creatr rec error : {ex.Message} ");
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"YYYY";

                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                        ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"CreateNewRecords error: {ex.Message}";

                                }
                            }
                            else
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += $"ZZZZ";

                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                    ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }

                        // GPT Checked 1
                        //// Completed
                        //// Read a records
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_ReadSpecificRecordsx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Reading specific records");

                            bool isEligibleAfterAssessment = false;

                            while (!hotCryptoServiceWithKeyOrder1.CryptoServiceStatus)
                                await Task.Delay(50);







                            byte[] pinRequirementBytes = null;

                            if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray != null)
                            {
                                pinRequirementBytes = (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray.ReadRecordsPINRequirement);
                            }
                            else
                            {
                                pinRequirementBytes = (await hotCryptoServiceWithKeyOrder1.DecryptWithCommonAgency(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.ActualUserConfigurationEncrypted.ReadRecordsPINRequirement));
                            };




                            if (UnicodeReaderMachine.ByteArrayToUnicodeAsync(pinRequirementBytes) == "1")
                            {
                                if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                                {
                                    try
                                    {
                                        CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);

                                        await hotCPMAccessKeyAgency.GetServerKeySet();
                                        while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                            await Task.Delay(50);

                                        await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();
                                        var accessResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                        if (accessResults.ComparisonResult == true)
                                        {
                                            await hotCPMAccessKeyAgency.ResetPINAttempted();
                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                            isEligibleAfterAssessment = true;
                                        }
                                        else
                                        {
                                            await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);

                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.NotAKeyAccess = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                            isEligibleAfterAssessment = false;
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"Model_ReadSpecificRecordsx error : {ex.Message}";
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                else
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"PIN is missing, please provide a key or contact customer service";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                isEligibleAfterAssessment = true;
                            }

                            if (isEligibleAfterAssessment)
                            {
                                try
                                {
                                    CryptoService hotCryptoServiceForRecords;

                                    Model_CampPasswordManagerEnterprise_Records tempModel_CPME_Records = await hotOracle_Object_Storage_Agency.CPMERecordsDownload();

                                    Guid recordsID = new Guid();

                                    if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_ReadSpecificRecordsx.PersonalKeyTaken != null)
                                    {
                                        hotCryptoServiceForRecords = new CryptoService(tempModel_CampMember_ServiceContext, 2, tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_ReadSpecificRecordsx.PersonalKeyTaken, tempMain_CPME_Request_FromClient.PublicKey, null);
                                    }
                                    else
                                    {
                                        hotCryptoServiceForRecords = new CryptoService(tempModel_CampMember_ServiceContext, 2, null, tempMain_CPME_Request_FromClient.PublicKey, null);
                                    }

                                    while (!hotCryptoServiceForRecords.CryptoServiceStatus)
                                    {
                                        if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.PersonalKeyMightNotBeAKey == true)
                                            break;

                                        await Task.Delay(50);
                                    }

                                    if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.PersonalKeyMightNotBeAKey == true)
                                    {
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.NotAKeyAccess = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);

                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    }
                                    else
                                    {
                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "AAAAA");

                                        recordsID = UnicodeReaderMachine.ConvertByteArrayToGuid(await hotCryptoServiceForRecords.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_ReadSpecificRecordsx.EncryptedUniqueIdentifier));

                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "BBBBB");

                                        Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID matchedRecord = tempModel_CPME_Records?.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx?.FirstOrDefault(r => r.UniqueIdentifier == recordsID);

                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);

                                        try
                                        {
                                            tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.Model_SpecificRecord_ByteArrayx = await hotCryptoServiceForRecords.AdjustmentForSendBackToClient(matchedRecord);
                                        }
                                        catch
                                        {
                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.KeyAccessIsMismatched = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);

                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        }
                                    }

                                    tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_RecordsID_TryDecryptResultx.RecordsID = recordsID;

                                }
                                catch (Exception ex)
                                {
                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Model_ReadSpecificRecordsx error : {ex.Message}";
                                }

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Read specific records RuntoEnd");

                            }
                            else
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }

                        // GPT Checked 1
                        //// Completed
                        //// Update a records
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Updating records");

                            bool isEligibleAfterAssessment = false;

                            while (!hotCryptoServiceWithKeyOrder1.CryptoServiceStatus)
                                await Task.Delay(50);









                            string pinRequirement = null;

                            if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray != null)
                            {
                                pinRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray.UpdateRecordsPINRequirement);
                            }
                            else
                            {
                                pinRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(await hotCryptoServiceWithKeyOrder1.DecryptWithCommonAgency(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.ActualUserConfigurationEncrypted.UpdateRecordsPINRequirement));
                            };


                            if (pinRequirement == "1")
                            {
                                var pinEncrypted = tempMain_CPME_Request_FromClient
                                    .Main_Configurations_FromClientx
                                    .Main_AccountAccessRecoverySet_FromClientx
                                    .Configuration_AccountRecovery_PINFromClient_Encryptedx;

                                if (pinEncrypted != null)
                                {
                                    try
                                    {
                                        CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, pinEncrypted);
                                        Task[] pinTasks = new Task[]
                                        {
                    hotCPMAccessKeyAgency.GetServerKeySet()
                                        };
                                        await Task.WhenAll(pinTasks);

                                        while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                            await Task.Delay(50);

                                        await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();

                                        if (hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults?.ComparisonResult == true)
                                        {
                                            await hotCPMAccessKeyAgency.ResetPINAttempted();
                                            isEligibleAfterAssessment = true;
                                        }
                                        else
                                        {
                                            await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                            isEligibleAfterAssessment = false;
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"Model_UpdateRecordsx error : {ex.Message}";
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                else
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                isEligibleAfterAssessment = true;
                            }

                            if (isEligibleAfterAssessment)




                            {
                                CryptoService hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 2, null, null, null);
                                CryptoService hotCryptoService8 = null;
                                bool useKey = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.PersonalKeyThatBeingUsed != null;

                                if (useKey)
                                    hotCryptoService8 = new CryptoService(tempModel_CampMember_ServiceContext, null, tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.PersonalKeyThatBeingUsed, null, null);

                                Model_CampPasswordManagerEnterprise_Records tempModel_CPME_Records = await hotOracle_Object_Storage_Agency.CPMERecordsDownload();

                                while (!hotCryptoService.CryptoServiceStatus || (useKey && !hotCryptoService8.CryptoServiceStatus))
                                    await Task.Delay(50);

                                Guid targetID = UnicodeReaderMachine.ConvertByteArrayToGuid(await hotCryptoService
                                    .DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.UniqueIdentifier));

                                Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID matchedRecord = tempModel_CPME_Records
                                    .ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx
                                    .FirstOrDefault(r => r.UniqueIdentifier == targetID);







                                var favoriteTask = hotCryptoService.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.FavoriteIndicator);

                                var providerNameTask = hotCryptoService.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.ProviderName);

                                var accountNameTask = hotCryptoService.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.AccountName);

                                var revealCounterTask = hotCryptoService.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.RevealingCounterForAccountName);

                                var providerUrlTask = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.PersonalKeyThatBeingUsed != null
                                    ? hotCryptoService.DecryptWithSpecialAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.ProviderURL)
                                    : hotCryptoService.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.ProviderURL);


                                var passwordTask = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.PersonalKeyThatBeingUsed != null
                                    ? hotCryptoService.DecryptWithSpecialAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.Password)
                                    : hotCryptoService.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.Password);

                                await Task.WhenAll(providerNameTask, providerUrlTask, accountNameTask, revealCounterTask, passwordTask);











                                string favoriteIndicatorString = UnicodeReaderMachine.ByteArrayToUnicodeAsync(await favoriteTask);

                                bool favoriteIndicator = false;

                                if (favoriteIndicatorString == "1")
                                {
                                    favoriteIndicator = true;
                                }



                                tempMain_Cache_CampPasswordManagerEnterprise.isUpdateRecordsAFavorited = favoriteIndicator;


















                                if (matchedRecord != null)
                                {
                                    try
                                    {
                                        DateTime now = DateTime.Now;
                                        matchedRecord.UpdatedDate = useKey
                                            ? await hotCryptoService8.EncryptWithSpecialAgency(DateTimeConversionMachine.DateTimeToBytes(now))
                                            : await hotCryptoService.EncryptWithCommonAgency(DateTimeConversionMachine.DateTimeToBytes(now));

                                        matchedRecord.FavoriteIndicator = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.FavoriteIndicator;
                                        matchedRecord.ProviderName = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.ProviderName;
                                        matchedRecord.ProviderURL = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.ProviderURL;
                                        matchedRecord.AccountName = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.AccountName;
                                        matchedRecord.RevealingCounterForAccountName = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.RevealingCounterForAccountName;
                                        matchedRecord.EncryptedPassword = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_UpdateRecordsx.Password;

                                        await hotOracle_Object_Storage_Agency.CPMERecordsOverwrite(tempModel_CPME_Records);
                                    }
                                    catch (Exception ex)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"Model_UpdateRecordsx error : {ex.Message}";
                                    }
                                }





                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                    ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                            }
                            else
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                    ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }






                        }

                        // GPT Checked 1
                        //// Completed
                        //// Copy Password to clipboard
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CopyPasswordx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Copying password");

                            bool isEligibleAfterAssessment = false;

                            while (!hotCryptoServiceWithKeyOrder1.CryptoServiceStatus)
                            {
                                await Task.Delay(50);
                            }





                            string CopyPasswordRecordsPINRequirement = null;

                            if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray != null)
                            {
                                CopyPasswordRecordsPINRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray.CopyPasswordRecordsPINRequirement);
                            }
                            else
                            {
                                CopyPasswordRecordsPINRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(await hotCryptoServiceWithKeyOrder1.DecryptWithCommonAgency(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.ActualUserConfigurationEncrypted.CopyPasswordRecordsPINRequirement));
                            };





                            if (CopyPasswordRecordsPINRequirement == "1")
                            {
                                if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                                {
                                    try
                                    {
                                        CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext,
                                            tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);

                                        Task serverKeySetTask = hotCPMAccessKeyAgency.GetServerKeySet();
                                        while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                        {
                                            await Task.Delay(50);
                                        }
                                        await serverKeySetTask;
                                        await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();

                                        Configuration_CampMember_AccessServiceResults tempConfiguration_AccessServiceResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                        if (tempConfiguration_AccessServiceResults.ComparisonResult == true)
                                        {
                                            await hotCPMAccessKeyAgency.ResetPINAttempted();
                                            isEligibleAfterAssessment = true;
                                        }
                                        else
                                        {
                                            await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                            isEligibleAfterAssessment = false;
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"Model_CopyPasswordx error : {ex.Message}";
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                else
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                isEligibleAfterAssessment = true;
                            }

                            if (isEligibleAfterAssessment)
                            {
                                try
                                {
                                    CryptoService hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 2, null, tempMain_CPME_Request_FromClient.PublicKey, null);

                                    if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CopyPasswordx.PersonalKeyTaken != null)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += "Into Personal Key records";

                                        CryptoService hotCryptoService2 = new CryptoService(tempModel_CampMember_ServiceContext, null, tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CopyPasswordx.PersonalKeyTaken, tempMain_CPME_Request_FromClient.PublicKey, null);

                                        Task<Model_CampPasswordManagerEnterprise_Records?> downloadTask = hotOracle_Object_Storage_Agency.CPMERecordsDownload();
                                        Task waitHot0 = Task.Run(async () =>
                                        {
                                            while (!hotCryptoService.CryptoServiceStatus) await Task.Delay(50);
                                        });
                                        Task waitHot1 = Task.Run(async () =>
                                        {
                                            while (!hotCryptoService2.CryptoServiceStatus) await Task.Delay(50);
                                        });

                                        await Task.WhenAll(downloadTask, waitHot0);
                                        Model_CampPasswordManagerEnterprise_Records tempModel_CPME_Records = downloadTask.Result;

                                        Guid targetRecordsID = UnicodeReaderMachine.ConvertByteArrayToGuid(
                                            await hotCryptoService.DecryptWithCommonAgency(
                                                tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CopyPasswordx.UniqueIdentifier));

                                        Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID matchedRecord = tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx
                                            .FirstOrDefault(r => r.UniqueIdentifier == targetRecordsID);

                                        Model_CampPasswordManagerEnterprise_JustPassword_Encrypted justPassword = new Model_CampPasswordManagerEnterprise_JustPassword_Encrypted();
                                        if (matchedRecord != null)
                                        {
                                            justPassword.Password = matchedRecord.EncryptedPassword;
                                        }









                                        byte[] favoriteRaw = await hotCryptoService.DecryptWithCommonAgency(matchedRecord.FavoriteIndicator);

                                        string favoriteIndicatorString = UnicodeReaderMachine.ByteArrayToUnicodeAsync(favoriteRaw);

                                        bool favoriteIndicator = false;

                                        if (favoriteIndicatorString == "1")
                                        {
                                            favoriteIndicator = true;
                                        }



                                        tempMain_Cache_CampPasswordManagerEnterprise.isCopyPasswordAFavorited = favoriteIndicator;





                                        DateTime now = DateTime.Now;

                                        if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CopyPasswordx.isCallOnlyForCaching != null)
                                        {
                                            matchedRecord.UpdatedDate = await hotCryptoService.EncryptWithCommonAgency(DateTimeConversionMachine.DateTimeToBytes(now));

                                            await hotOracle_Object_Storage_Agency.CPMERecordsOverwrite(tempModel_CPME_Records);
                                        }
                                        else
                                        {
                                            matchedRecord.UpdatedDate = await hotCryptoService.EncryptWithCommonAgency(DateTimeConversionMachine.DateTimeToBytes(now));

                                            await hotOracle_Object_Storage_Agency.CPMERecordsOverwrite(tempModel_CPME_Records);

                                            await waitHot1;
                                            tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.Model_JustPassword_ByteArrayx =
                                                await hotCryptoService2.AdjustmentForSendBackToClient(justPassword, true);
                                        }


                                    }
                                    else
                                    {
                                        Task<Model_CampPasswordManagerEnterprise_Records?> downloadTask = hotOracle_Object_Storage_Agency.CPMERecordsDownload();
                                        Task waitHot0 = Task.Run(async () =>
                                        {
                                            while (!hotCryptoService.CryptoServiceStatus) await Task.Delay(50);
                                        });

                                        await Task.WhenAll(downloadTask, waitHot0);
                                        Model_CampPasswordManagerEnterprise_Records tempModel_CPME_Records = downloadTask.Result;

                                        Guid targetRecordsID = UnicodeReaderMachine.ConvertByteArrayToGuid(
                                            await hotCryptoService.DecryptWithCommonAgency(
                                                tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CopyPasswordx.UniqueIdentifier));

                                        Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID matchedRecord = tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx
                                            .FirstOrDefault(r => r.UniqueIdentifier == targetRecordsID);

                                        Model_CampPasswordManagerEnterprise_JustPassword_Encrypted justPassword = new Model_CampPasswordManagerEnterprise_JustPassword_Encrypted();
                                        if (matchedRecord != null)
                                        {
                                            justPassword.Password = matchedRecord.EncryptedPassword;
                                        }




                                        DateTime now = DateTime.Now;

                                        if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CopyPasswordx.isCallOnlyForCaching != null)
                                        {
                                            matchedRecord.UpdatedDate = await hotCryptoService.EncryptWithCommonAgency(DateTimeConversionMachine.DateTimeToBytes(now));

                                            await hotOracle_Object_Storage_Agency.CPMERecordsOverwrite(tempModel_CPME_Records);
                                        }
                                        else
                                        {
                                            matchedRecord.UpdatedDate = await hotCryptoService.EncryptWithCommonAgency(DateTimeConversionMachine.DateTimeToBytes(now));

                                            await hotOracle_Object_Storage_Agency.CPMERecordsOverwrite(tempModel_CPME_Records);

                                            await waitHot0;
                                            tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.Model_JustPassword_ByteArrayx =
                                                await hotCryptoService.AdjustmentForSendBackToClient(justPassword, true);
                                        }

                                    }

                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                        ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                }
                                catch (Exception ex)
                                {
                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                        ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Model_CopyPasswordx error : {ex.Message}";
                                }
                            }
                            else
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                    ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }





                        // GPT Checked 1
                        //// Completed
                        //// Move Records to BIN
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_MoveRecordsToBINx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Moving records to bin");

                            bool? isEligibleAfterAssessment = false;

                            // Wait for crypto service ready
                            while (!hotCryptoServiceWithKeyOrder1.CryptoServiceStatus)
                                await Task.Delay(50);








                            string MoveRecordsToBinPINRequirement = null;

                            if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray != null)
                            {
                                MoveRecordsToBinPINRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray.MoveRecordsToBinPINRequirement);
                            }
                            else
                            {
                                MoveRecordsToBinPINRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(await hotCryptoServiceWithKeyOrder1.DecryptWithCommonAgency(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.ActualUserConfigurationEncrypted.MoveRecordsToBinPINRequirement));
                            };




                            if (MoveRecordsToBinPINRequirement == "1")
                            {
                                if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                                {
                                    try
                                    {
                                        var hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext,
                                            tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);
                                        await hotCPMAccessKeyAgency.GetServerKeySet();

                                        while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                            await Task.Delay(50);

                                        await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();
                                        var accessResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                        isEligibleAfterAssessment = accessResults.ComparisonResult;
                                        if (isEligibleAfterAssessment == true)
                                        {
                                            await hotCPMAccessKeyAgency.ResetPINAttempted();
                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        }
                                        else
                                        {
                                            await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                        isEligibleAfterAssessment = false;
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    }
                                }
                                else
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                    isEligibleAfterAssessment = false;
                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                }
                            }
                            else
                            {
                                isEligibleAfterAssessment = true;
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                            }

                            if (isEligibleAfterAssessment == true)
                            {
                                try
                                {
                                    var hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 2, null, null, null);

                                    // Download records and decrypt identifier in parallel
                                    var downloadTask = hotOracle_Object_Storage_Agency.CPMERecordsDownload();
                                    var decryptIdTask = hotCryptoService.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_MoveRecordsToBINx.UniqueIdentifier);







                                    await Task.WhenAll(downloadTask, decryptIdTask);

                                    var tempModel_CPME_Records = downloadTask.Result;
                                    var targetID = UnicodeReaderMachine.ConvertByteArrayToGuid(decryptIdTask.Result);

                                    var matchedRecord = tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx.FirstOrDefault(r => r.UniqueIdentifier == targetID);









                                    string favoriteString = UnicodeReaderMachine.ByteArrayToUnicodeAsync(await hotCryptoService.DecryptWithCommonAgency(matchedRecord.FavoriteIndicator));

                                    bool isRecordsAFavorite = false;

                                    if(favoriteString == "1")
                                    {
                                        isRecordsAFavorite = true;
                                    }
                                    else
                                    {
                                        isRecordsAFavorite = false;
                                    }









                                    if (isRecordsAFavorite)
                                    {
                                        await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewAllCacheDelete();

                                        await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewFavoriteCacheDelete();

                                        await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewRecycleCacheDelete();

                                        tempMain_Cache_CampPasswordManagerEnterprise.isMoveRecordsToBinAFavorited = isRecordsAFavorite;
                                    }
                                    else
                                    {
                                        await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewAllCacheDelete();

                                        await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewRecycleCacheDelete();

                                        tempMain_Cache_CampPasswordManagerEnterprise.isMoveRecordsToBinAFavorited = isRecordsAFavorite;
                                    }










                                    if (matchedRecord != null)
                                    {
                                        matchedRecord.DeletionCall = DateTime.Now;
                                        await hotOracle_Object_Storage_Agency.CPMERecordsOverwrite(tempModel_CPME_Records);
                                    }
                                    else
                                    {
                                        // No record found; set failure
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        tempModel_CampMember_ServiceContext.ErrorMessage += "Record to move to BIN not found.";
                                    }





                                }
                                catch (Exception ex)
                                {
                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Error in MoveRecordsToBINx: {ex.Message}";
                                }
                            }
                        }



                        // GPT Checked 1
                        //// Completed
                        //// Fetching Feeds
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching records feeds");

                            bool isEligibleAfterAssessment = false;

                            if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode == 2)
                            {
                                while (!hotCryptoServiceWithKeyOrder1.CryptoServiceStatus)
                                {
                                    await Task.Delay(50);
                                }



                                string RecycleBinPINRequirement = null;

                                if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray != null)
                                {
                                    RecycleBinPINRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray.RecycleBinPINRequirement);
                                }
                                else
                                {
                                    RecycleBinPINRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(await hotCryptoServiceWithKeyOrder1.DecryptWithCommonAgency(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.ActualUserConfigurationEncrypted.RecycleBinPINRequirement));
                                };




                                if (RecycleBinPINRequirement == "1")
                                {
                                    if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                                    {
                                        try
                                        {
                                            CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);
                                            await hotCPMAccessKeyAgency.GetServerKeySet();

                                            while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                            {
                                                await Task.Delay(50);
                                            }

                                            await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();

                                            Configuration_CampMember_AccessServiceResults tempConfiguration_AccessServiceResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                            if (tempConfiguration_AccessServiceResults.ComparisonResult == true)
                                            {
                                                await hotCPMAccessKeyAgency.ResetPINAttempted();
                                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                                isEligibleAfterAssessment = true;
                                            }
                                            else
                                            {
                                                await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                                isEligibleAfterAssessment = false;
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                            isEligibleAfterAssessment = false;
                                        }
                                    }
                                    else
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                else
                                {
                                    isEligibleAfterAssessment = true;
                                }
                            }
                            else
                            {
                                isEligibleAfterAssessment = true;
                            }

                            if (isEligibleAfterAssessment)
                            {

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed AAAA");


                                CryptoService hotCryptoServiceForRecords = new CryptoService(tempModel_CampMember_ServiceContext, 2, null, tempMain_CPME_Request_FromClient.PublicKey, null);

                                try
                                {
                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed BBBB");

                                    Model_CampPasswordManagerEnterprise_Records? tempModel_CPME_Records = await hotOracle_Object_Storage_Agency.CPMERecordsDownload();

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed CCCC");

                                    List<Model_CampPasswordManagerEnterprise_LandingPage_AllMode_Encrypted_And_GUID> landingList = new List<Model_CampPasswordManagerEnterprise_LandingPage_AllMode_Encrypted_And_GUID>();

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed DDDD");

                                    if (tempModel_CPME_Records == null || tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx == null || tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx.Count() == 0)
                                    {
                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed EEEE");

                                        tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.ListModel_CampPasswordManagerEnterprise_LandingPage_Encryptedx = new List<Model_CampPasswordManagerEnterprise_LandingPage_Encrypted>();

                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);

                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed FFFF");
                                    }
                                    else
                                    {
                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed GGGG");

                                        var allRecords = tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx;

                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed HHHH");

                                        IEnumerable<Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID> filteredRecords;

                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed IIII");

                                        if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode == 0 || tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode == 1)
                                        {
                                            filteredRecords = allRecords.Where(r => r.DeletionCall == null);

                                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed JJJJ");
                                        }
                                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode == 2)
                                        {
                                            filteredRecords = allRecords.Where(r => r.DeletionCall != null);

                                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed KKKK");
                                        }
                                        else
                                        {
                                            filteredRecords = Enumerable.Empty<Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID>();

                                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed LLLL");
                                        }

                                        foreach (var record in filteredRecords)
                                        {
                                            landingList.Add(new Model_CampPasswordManagerEnterprise_LandingPage_AllMode_Encrypted_And_GUID
                                            {
                                                UniqueIdentifier = record.UniqueIdentifier,
                                                ProviderName = record.ProviderName,
                                                AccountName = record.AccountName,
                                                RevealingCounterForAccountName = record.RevealingCounterForAccountName,
                                                SpecialKeyIndicator = record.SpecialKeyIndicator,
                                                FavoriteIndicator = record.FavoriteIndicator,
                                                DeletionCall = record.DeletionCall
                                            });
                                        }

                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed MMMM");

                                        while (!hotCryptoServiceForRecords.CryptoServiceStatus)
                                        {
                                            await Task.Delay(50);
                                        }

                                        if(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode == 0)
                                        {
                                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Generate feed mode 0");

                                            (tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All, tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.ListModel_CampPasswordManagerEnterprise_LandingPage_Encryptedx) = await hotCryptoServiceForRecords.AdjustmentForSendBackToClient(landingList, tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode, tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.isCallOnlyForCaching);

                                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Generate feed mode 0 finished");
                                        }
                                        else if(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode == 1)
                                        {
                                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Generate feed mode 1");

                                            (tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite, tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.ListModel_CampPasswordManagerEnterprise_LandingPage_Encryptedx) = await hotCryptoServiceForRecords.AdjustmentForSendBackToClient(landingList, tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode, tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.isCallOnlyForCaching);

                                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Generate feed mode 1 finished");
                                        }
                                        else if(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode == 2)
                                        {
                                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Generate feed mode 2");

                                            (tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Recycle, tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.ListModel_CampPasswordManagerEnterprise_LandingPage_Encryptedx) = await hotCryptoServiceForRecords.AdjustmentForSendBackToClient(landingList, tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode, tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.isCallOnlyForCaching);

                                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Generate feed mode 2 finished");
                                        }

                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed Done");

                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);

                                        if (!(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode == 0
                                            || tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode == 1
                                            || tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode == 2))
                                        {
                                            tempModel_CampMember_ServiceContext.ErrorMessage += $"Unknown fetching mode: {tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode}";
                                        }

                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Fetching feed OOOO");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, $"Fetching feed EOORO 99  {ex.Message}");

                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Model_FetchingFeedsx : {ex.Message}";
                                }
                            }
                            else
                            {
                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, $"Fetching feed EOORO 666 ");

                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                tempModel_CampMember_ServiceContext.ErrorMessage += "Model_FetchingFeedsx Service failed";
                            }
                        }


                        // GPT Checked 1
                        //// Completed
                        //// Recover Records
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_RecoverRecordsx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Recovering records");

                            bool isEligibleAfterAssessment = false;

                            while (!hotCryptoServiceWithKeyOrder1.CryptoServiceStatus)
                            {
                                await Task.Delay(50);
                            }






                            string RecoverRecordPINRequirement = null;

                            if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray != null)
                            {
                                RecoverRecordPINRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray.RecoverRecordPINRequirement);
                            }
                            else
                            {
                                RecoverRecordPINRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(await hotCryptoServiceWithKeyOrder1.DecryptWithCommonAgency(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.ActualUserConfigurationEncrypted.RecoverRecordPINRequirement));
                            };



                            if (RecoverRecordPINRequirement == "1")
                            {
                                if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                                {
                                    try
                                    {
                                        CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);

                                        await hotCPMAccessKeyAgency.GetServerKeySet();

                                        while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                        {
                                            await Task.Delay(50);
                                        }

                                        await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();

                                        Configuration_CampMember_AccessServiceResults tempConfiguration_AccessServiceResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                        if (tempConfiguration_AccessServiceResults.ComparisonResult == true)
                                        {
                                            await hotCPMAccessKeyAgency.ResetPINAttempted();
                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                            isEligibleAfterAssessment = true;
                                        }
                                        else
                                        {
                                            await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                            isEligibleAfterAssessment = false;
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                else
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                isEligibleAfterAssessment = true;
                            }

                            if (isEligibleAfterAssessment)
                            {
                                try
                                {
                                    CryptoService hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 2, null, null, null);

                                    Model_CampPasswordManagerEnterprise_Records tempModel_CPME_Records = await hotOracle_Object_Storage_Agency.CPMERecordsDownload();

                                    Guid targetRecordsID = UnicodeReaderMachine.ConvertByteArrayToGuid(
                                        await hotCryptoService.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_RecoverRecordsx.UniqueIdentifier));

                                    Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID? matchedRecord = tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx.FirstOrDefault(r => r.UniqueIdentifier == targetRecordsID);







                                    string favoriteString = UnicodeReaderMachine.ByteArrayToUnicodeAsync(await hotCryptoService.DecryptWithCommonAgency(matchedRecord.FavoriteIndicator));

                                    bool isRecordsAFavorite = false;

                                    if (favoriteString == "1")
                                    {
                                        isRecordsAFavorite = true;
                                    }
                                    else
                                    {
                                        isRecordsAFavorite = false;
                                    }








                                    if (isRecordsAFavorite)
                                    {
                                        await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewAllCacheDelete();

                                        await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewFavoriteCacheDelete();

                                        await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewRecycleCacheDelete();

                                        tempMain_Cache_CampPasswordManagerEnterprise.isRecoverRecordsAFavorited = isRecordsAFavorite;
                                    }
                                    else
                                    {
                                        await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewAllCacheDelete();

                                        await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewRecycleCacheDelete();

                                        tempMain_Cache_CampPasswordManagerEnterprise.isRecoverRecordsAFavorited = isRecordsAFavorite;
                                    }








                                    if (matchedRecord != null)
                                    {
                                        matchedRecord.DeletionCall = null;
                                    }

                                    await hotOracle_Object_Storage_Agency.CPMERecordsOverwrite(tempModel_CPME_Records);

                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                }
                                catch (Exception ex)
                                {
                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Model_RecoverRecordsx error: {ex.Message}";
                                }
                            }
                            else
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }





                        // GPT Checked 1
                        //// Completed
                        //// Permanent Delete Records
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_PermanentDeleteRecordsx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Permanently delete records");

                            bool isEligibleAfterAssessment = false;

                            while (!hotCryptoServiceWithKeyOrder1.CryptoServiceStatus)
                            {
                                await Task.Delay(50);
                            }




                            string PermanentDeleteRecordsPINRequirement = null;

                            if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray != null)
                            {
                                PermanentDeleteRecordsPINRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.CampMember_Configuration_Filtered_ByteArray.PermanentDeleteRecordsPINRequirement);
                            }
                            else
                            {
                                PermanentDeleteRecordsPINRequirement = UnicodeReaderMachine.ByteArrayToUnicodeAsync(await hotCryptoServiceWithKeyOrder1.DecryptWithCommonAgency(tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.ActualUserConfigurationEncrypted.PermanentDeleteRecordsPINRequirement));
                            };



                            if (PermanentDeleteRecordsPINRequirement == "1")
                            {
                                if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                                {
                                    try
                                    {
                                        CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);

                                        await hotCPMAccessKeyAgency.GetServerKeySet();

                                        while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                        {
                                            await Task.Delay(50);
                                        }

                                        await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();

                                        Configuration_CampMember_AccessServiceResults tempConfiguration_AccessServiceResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                        if (tempConfiguration_AccessServiceResults.ComparisonResult == true)
                                        {
                                            await hotCPMAccessKeyAgency.ResetPINAttempted();
                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                            isEligibleAfterAssessment = true;
                                        }
                                        else
                                        {
                                            await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                            isEligibleAfterAssessment = false;
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                else
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                isEligibleAfterAssessment = true;
                            }

                            if (isEligibleAfterAssessment)
                            {
                                try
                                {
                                    CryptoService hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 2, null, null, null);

                                    Model_CampPasswordManagerEnterprise_Records tempModel_CPME_Records = await hotOracle_Object_Storage_Agency.CPMERecordsDownload();

                                    Guid targetRecordsID = UnicodeReaderMachine.ConvertByteArrayToGuid(
                                        await hotCryptoService.DecryptWithCommonAgency(
                                            tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_PermanentDeleteRecordsx.UniqueIdentifier));

                                    var recordToRemove = tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx
                                        .FirstOrDefault(r => r.UniqueIdentifier == targetRecordsID);








                                    await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewRecycleCacheDelete();







                                    if (recordToRemove != null)
                                    {
                                        tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx.Remove(recordToRemove);
                                    }

                                    await hotOracle_Object_Storage_Agency.CPMERecordsOverwrite(tempModel_CPME_Records);

                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                }
                                catch (Exception ex)
                                {
                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Model_PermanentDeleteRecordsx error: {ex.Message}";
                                }
                            }
                            else
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }









                        // GPT Checked 1
                        //// Completed
                        //// Update user configurations
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_Update_CPMUserConfigurationsx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Updating user configurations");

                            bool isEligibleAfterAssessment = false;

                            if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                            {
                                try
                                {
                                    var hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);
                                    await hotCPMAccessKeyAgency.GetServerKeySet();
                                    while (!hotCPMAccessKeyAgency.CryptoServiceStatus) await Task.Delay(50);
                                    await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();
                                    var result = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                    if (result.ComparisonResult == true)
                                    {
                                        await hotCPMAccessKeyAgency.ResetPINAttempted();
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        isEligibleAfterAssessment = true;
                                    }
                                    else
                                    {
                                        await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                isEligibleAfterAssessment = false;
                            }

                            if (isEligibleAfterAssessment)
                            {








                                try
                                {
                                    Configuration_CampMember_Encrypted? configEncrypted = await hotOracle_Object_Storage_Agency.CPMEUserConfigDownload();

                                    CryptoService hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 1, null, null, null);
                                    while (!hotCryptoService.CryptoServiceStatus)
                                    {
                                        await Task.Delay(50);
                                    }


                                    DateTime tempDateTime = DateTime.Now;

                                    byte[] nowEncrypted = await hotCryptoService.EncryptWithCommonAgency(DateTimeConversionMachine.DateTimeToBytes(tempDateTime));




                                    Model_CampMember_Update_UserConfigurations update = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_Update_CPMUserConfigurationsx;
                                    Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResult decryptResult = new Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResult();

                                    decryptResult.updateDateTime = DateTimeConversionMachine.DateTimeToBytes(tempDateTime);

                                    // fixed array of mappings
                                    (byte[]? field, Action<byte[]> setConfig, Action<byte[]> setResult)[] fieldMap =
                                    {
                                        (update.ForceCPMLoginRequirement,
                                            v => configEncrypted.ForceCPMLoginRequirement = v,
                                            v => decryptResult.decryptedForceCPMLoginRequirement = v),
                                      (update.LoginCPMKeyRequirement,
                                          v => configEncrypted.LoginCPMKeyRequirement = v,
                                          v => decryptResult.decryptedLoginCPMKeyRequirement = v),
                                      (update.LoginPINRequirement,
                                          v => configEncrypted.LoginPINRequirement = v,
                                          v => decryptResult.decryptedLoginPINRequirement = v),
                                      (update.MakeHotFavoritePINRequirement,
                                          v => configEncrypted.MakeHotFavoritePINRequirement = v,
                                          v => decryptResult.decryptedMakeHotFavoritePINRequirement = v),
                                      (update.CreateNewRecordsPINRequirement,
                                          v => configEncrypted.CreateNewRecordsPINRequirement = v,
                                          v => decryptResult.decryptedCreateNewRecordsPINRequirement = v),
                                      (update.ReadRecordsPINRequirement,
                                          v => configEncrypted.ReadRecordsPINRequirement = v,
                                          v => decryptResult.decryptedReadRecordsPINRequirement = v),
                                      (update.UpdateRecordsPINRequirement,
                                          v => configEncrypted.UpdateRecordsPINRequirement = v,
                                          v => decryptResult.decryptedUpdateRecordsPINRequirement = v),
                                      (update.CopyPasswordRecordsPINRequirement,
                                          v => configEncrypted.CopyPasswordRecordsPINRequirement = v,
                                          v => decryptResult.decryptedCopyPasswordRecordsPINRequirement = v),
                                      (update.MoveRecordsToBinPINRequirement,
                                          v => configEncrypted.MoveRecordsToBinPINRequirement = v,
                                          v => decryptResult.decryptedMoveRecordsToBinPINRequirement = v),
                                      (update.RecycleBinPINRequirement,
                                          v => configEncrypted.RecycleBinPINRequirement = v,
                                          v => decryptResult.decryptedRecycleBinPINRequirement = v),
                                      (update.RecoverRecordPINRequirement,
                                          v => configEncrypted.RecoverRecordPINRequirement = v,
                                          v => decryptResult.decryptedRecoverRecordPINRequirement = v),
                                      (update.PermanentDeleteRecordsPINRequirement,
                                          v => configEncrypted.PermanentDeleteRecordsPINRequirement = v,
                                          v => decryptResult.decryptedPermanentDeleteRecordsPINRequirement = v),
                                      (update.NewPIN,
                                          v => configEncrypted.Pin0 = v,
                                          v => decryptResult.decryptedNewPIN = v),
                                      (update.NewSessionTime,
                                          v => configEncrypted.SessionMinuteForHotLoginObject = v,
                                          v => decryptResult.decryptedNewSessionTime = v)
                                    };

                                    foreach (var (field, setConfig, setResult) in fieldMap)
                                    {
                                        if (field != null)
                                        {
                                            try
                                            {
                                                byte[] decrypted = await hotCryptoService.DecryptWithCommonAgency(field);
                                                setResult(decrypted);
                                                setConfig(field);
                                                configEncrypted.UpdateDate = nowEncrypted;
                                                await hotOracle_Object_Storage_Agency.CPMEUserConfigOverwrite(configEncrypted);
                                            }
                                            catch
                                            {
                                                tempModel_CampMember_ServiceContext.ErrorMessage += "Data is not meant for this user.";
                                            }
                                            break; // process only one update field
                                        }
                                    }

                                    tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx = decryptResult;

                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                        ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                }
                                catch (Exception ex)
                                {
                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                        ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                }













                            }
                            else
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }














                        // GPT Checked 1
                        //// BLOB NOW !
                        //// Signed T&C and Privacy Statement, Make update, and Send an email as a copy.
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_TNCPVCSignedProtectedSHAandMakeDeclarationx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Signing T&C and Privacy statements");

                            Configuration_CampMember_Encrypted tempConfiguration_CampMember_Encrypted = await hotOracle_Object_Storage_Agency.CPMEUserConfigDownload();

                            tempConfiguration_CampMember_Encrypted.TNCPVESignedFromUser = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_TNCPVCSignedProtectedSHAandMakeDeclarationx.actualTNCPVEScrapingFromCustomerInteraction;

                            await hotOracle_Object_Storage_Agency.CPMEUserConfigOverwrite(tempConfiguration_CampMember_Encrypted);

                            try
                            {
                                CampCommercialServer_Crypto_agency hotCampCryptoAgency = new CampCommercialServer_Crypto_agency(tempModel_CampMember_ServiceContext);

                                await hotCampCryptoAgency.RetriveAKey(1, null, null, null, false);

                                string userEmail = Server_UserProfileReaderMachine.GetEmail(tempModel_CampMember_ServiceContext.HttpRequestx);
                                string userActualName = Server_UserProfileReaderMachine.Get_UserActualName(tempModel_CampMember_ServiceContext.HttpRequestx);

                                tempMain_Cache_CampPasswordManagerEnterprise.CampMember_Configuration_Filtered_ByteArrayx.TNCPVESignedFromUser = await hotCampCryptoAgency.DecryptDatawithStaticRSA(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_TNCPVCSignedProtectedSHAandMakeDeclarationx.actualTNCPVEScrapingFromCustomerInteraction);

                                CampCommercialServer_EmailAgency hotCampMember_EmailAgency = new CampCommercialServer_EmailAgency(tempModel_CampMember_ServiceContext);
                                await hotCampMember_EmailAgency.SendAccessObjectToEmail(userEmail, userActualName, tempMain_Cache_CampPasswordManagerEnterprise.CampMember_Configuration_Filtered_ByteArrayx.TNCPVESignedFromUser, tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_TNCPVCSignedProtectedSHAandMakeDeclarationx);

                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                            }
                            catch (Exception ex)
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                            }
                        }



                        // GPT Checked 1
                        // BLOB NOW!
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CPME_Request_Nessary_Keyx != null)
                        {
                            try
                            {
                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Retrieving necessary key");

                                CampCommercialServer_AccessKey_agency hotAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, null);

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Necessary key AAAA");

                                Model_CampMember_NecessaryKey_ByteArray tempModel_NecessaryKey = await hotAccessKeyAgency.GetDefaultPublicKey(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CPME_Request_Nessary_Keyx);

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Necessary key BBBB");

                                CryptoService hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, null, null, tempMain_CPME_Request_FromClient.PublicKey, null);

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Necessary key CCCC");

                                tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.Model_NecessaryKeyx = await hotCryptoService.AdjustmentForSendBackToClient(tempModel_NecessaryKey);

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Necessary key DDDD");


                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                            }
                            catch (Exception ex)
                            {
                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, $"Necessary key {ex.Message}");

                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                tempModel_CampMember_ServiceContext.ErrorMessage += $"Model_CPME_Request_Nessary_Keyx error : {ex.Message}";
                            }
                        }





                        // GPT Checked 1
                        //// Completed
                        //// Revoke EntraID session
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_RequestRevokeServerSessionx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Revoking user session");

                            bool isEligibleAfterAssessment = false;

                            if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                            {
                                try
                                {
                                    CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);
                                    await hotCPMAccessKeyAgency.GetServerKeySet();
                                    while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                    {
                                        await Task.Delay(50);
                                    }
                                    await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();
                                    var tempConfiguration_AccessServiceResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                    if (tempConfiguration_AccessServiceResults.ComparisonResult == true)
                                    {
                                        await hotCPMAccessKeyAgency.ResetPINAttempted();
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        isEligibleAfterAssessment = true;
                                    }
                                    else
                                    {
                                        await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                isEligibleAfterAssessment = false;
                            }

                            if (isEligibleAfterAssessment)
                            {
                                //try
                                //{
                                //    EntraIDAdminAgency hotEntraIDAdminAgency = new EntraIDAdminAgency(tempModel_CampMember_ServiceContext);

                                //    try
                                //    {
                                //        await hotEntraIDAdminAgency.RevokeUserSession();
                                //    }
                                //    catch (Exception ex)
                                //    {
                                //        tempModel_CampMember_ServiceContext.ErrorMessage += $"Failed to authenticate point person admin: {ex.Message}";
                                //    }
                                //}
                                //catch (Exception ex)
                                //{
                                //    tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                //    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                //}
                            }
                            else
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }




                        // GPT Checked 1
                        // Completed
                        //// Permanent delete an account
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_RequestPermanentDeleteAccountx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Permanently delete account request");

                            bool isEligibleAfterAssessment = false;

                            if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                            {
                                try
                                {
                                    CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);
                                    await hotCPMAccessKeyAgency.GetServerKeySet();
                                    while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                    {
                                        await Task.Delay(50);
                                    }
                                    await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();
                                    var tempConfiguration_AccessServiceResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                    if (tempConfiguration_AccessServiceResults.ComparisonResult == true)
                                    {
                                        await hotCPMAccessKeyAgency.ResetPINAttempted();
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        isEligibleAfterAssessment = true;
                                    }
                                    else
                                    {
                                        await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                isEligibleAfterAssessment = false;
                            }

                            if (isEligibleAfterAssessment)
                            {
                                try
                                {
                                    await hotOracle_Object_Storage_Agency.CPMEUserConfigDelete();
                                    await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserKeysDelete();
                                    await hotOracle_Object_Storage_Agency.CPMERecordsDelete();


                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                }
                                catch (Exception ex)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                }
                            }
                            else
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }






                        // GPT Checked 1
                        //// Completed
                        //// Cancel subscription
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CancelSubscriptionx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Cancelling subscription");

                            bool isEligibleAfterAssessment = false;

                            if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                            {
                                try
                                {
                                    CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);
                                    await hotCPMAccessKeyAgency.GetServerKeySet();
                                    while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                    {
                                        await Task.Delay(50);
                                    }
                                    await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();
                                    var tempConfiguration_AccessServiceResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                    if (tempConfiguration_AccessServiceResults.ComparisonResult == true)
                                    {
                                        await hotCPMAccessKeyAgency.ResetPINAttempted();
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        isEligibleAfterAssessment = true;
                                    }
                                    else
                                    {
                                        await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                isEligibleAfterAssessment = false;
                            }

                            if (isEligibleAfterAssessment)
                            {
                                CampCommercialServer_Stripe_agency hotStripeAgency = new CampCommercialServer_Stripe_agency(tempModel_CampMember_ServiceContext);

                                try
                                {
                                    await hotStripeAgency.CancelFirstActiveSubscriptionWithEndOfCycleService();
                                }
                                catch (Exception ex)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                }
                            }
                            else
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }






                        // GPT Checked 1
                        //// Completed
                        //// Cancel cancellation subscription
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_CancelCancellationx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Resumimg subscription");

                            bool isEligibleAfterAssessment = false;
                            if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                            {
                                try
                                {
                                    CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);
                                    await hotCPMAccessKeyAgency.GetServerKeySet();
                                    while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                    {
                                        await Task.Delay(50);
                                    }
                                    await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();
                                    var tempConfiguration_AccessServiceResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                    if (tempConfiguration_AccessServiceResults.ComparisonResult == true)
                                    {
                                        await hotCPMAccessKeyAgency.ResetPINAttempted();
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        isEligibleAfterAssessment = true;
                                    }
                                    else
                                    {
                                        await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                isEligibleAfterAssessment = false;
                            }

                            if (isEligibleAfterAssessment)
                            {
                                CampCommercialServer_Stripe_agency hotStripeAgency = new CampCommercialServer_Stripe_agency(tempModel_CampMember_ServiceContext);
                                try
                                {
                                    await hotStripeAgency.CancelCancellationDeclarationOut();
                                }
                                catch (Exception ex)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                }
                            }
                            else
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }





                        // GPT Checked 1
                        //// Dev
                        //// Request session to buy a goods
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_ReqSessionToBuyAGoods_Encryptedx != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Requesting CampStore session");

                            bool isEligibleAfterAssessment = false;
                            if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                            {
                                try
                                {
                                    CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);
                                    await hotCPMAccessKeyAgency.GetServerKeySet();
                                    while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                    {
                                        await Task.Delay(50);
                                    }
                                    await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();
                                    var tempConfiguration_AccessServiceResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                    if (tempConfiguration_AccessServiceResults.ComparisonResult == true)
                                    {
                                        await hotCPMAccessKeyAgency.ResetPINAttempted();
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        isEligibleAfterAssessment = true;
                                    }
                                    else
                                    {
                                        await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += $"PIN is missing, please provide a key or contact customer service";
                                isEligibleAfterAssessment = false;
                            }

                            if (isEligibleAfterAssessment)
                            {
                                CampCommercialServer_Stripe_agency hotStripeAgency = new CampCommercialServer_Stripe_agency(tempModel_CampMember_ServiceContext);

                                int productToBePurchase = ByteArrayAndConversionMachine.ConvertUnicodeBytesToInt32(await hotCryptoServiceWithKeyOrder1.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_ReqSessionToBuyAGoods_Encryptedx.WhatToBuy));
                                int quantityToPurchase = ByteArrayAndConversionMachine.ConvertUnicodeBytesToInt32(await hotCryptoServiceWithKeyOrder1.DecryptWithCommonAgency(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_ReqSessionToBuyAGoods_Encryptedx.Quantity));

                                Model_CampStore_ReturnedSessionToBuyAGoods_ByteArray tempModel_ReturnedSessionToBuyAGoods_ByteArray = new Model_CampStore_ReturnedSessionToBuyAGoods_ByteArray();


                                // Recurring 9.99 USD a month
                                if (productToBePurchase == 1)
                                {
                                    string sessionString = await hotStripeAgency.CreateRecurringCheckoutSession("price_1Pqu5HEgetNpsvbVClzUlNRQ", quantityToPurchase);
                                    tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                                }
                                // Recurring 299 USD / 3 years
                                else if (productToBePurchase == 2)
                                {
                                    string sessionString = await hotStripeAgency.CreateRecurringCheckoutSession("price_1Pqu3pEgetNpsvbVS7lOUlFZ", quantityToPurchase);
                                    tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                                }
                                // 1 USD 2048 key
                                else if (productToBePurchase == 4)
                                {
                                    string sessionString = await hotStripeAgency.CreateHotPaymentCheckoutSession("price_1Q6GxaEgetNpsvbV8f53yoX1", quantityToPurchase);
                                    tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                                }
                                // 4 USD 30XX key
                                else if (productToBePurchase == 5)
                                {
                                    string sessionString = await hotStripeAgency.CreateHotPaymentCheckoutSession("price_1Q6GxoEgetNpsvbVFhDdcylW", quantityToPurchase);
                                    tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                                }
                                // 5 USD 4096 Key
                                else if (productToBePurchase == 6)
                                {
                                    string sessionString = await hotStripeAgency.CreateHotPaymentCheckoutSession("price_1Q6GxxEgetNpsvbV9nIDAScw", quantityToPurchase);
                                    tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                                }
                                // Recurring 1.99 a month
                                else if (productToBePurchase == 7)
                                {
                                    string sessionString = await hotStripeAgency.CreateRecurringCheckoutSession("price_1R0n9pEgetNpsvbVUQPtm4Cd", quantityToPurchase);
                                    tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                                }
                                // Recurring 59 USD / 3 years
                                else if (productToBePurchase == 8)
                                {
                                    string sessionString = await hotStripeAgency.CreateRecurringCheckoutSession("price_1R0nAnEgetNpsvbVEOBfGFnV", quantityToPurchase);
                                    tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                                }
                                // Lifetime 599 USD
                                else if (productToBePurchase == 999)
                                {
                                    CampCommercialServer_Stripe_agency hotStripeAgency999 = new CampCommercialServer_Stripe_agency(tempModel_CampMember_ServiceContext);

                                    string sessionString = await hotStripeAgency.CreateHotPaymentCheckoutSession("price_1Q87BMEgetNpsvbVPwgdx0vo", 1);
                                    tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                                }

                                tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.Model_ReturnedSessionToBuyAGoods_ByteArrayx = tempModel_ReturnedSessionToBuyAGoods_ByteArray;
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                            }
                            else
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }




                        // GPT Checked 1
                        //// Dev
                        //// Distribute key into database and send through email
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_KeysDistributionAfterPurchasex != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Distributing keys");

                            bool isEligibleAfterAssessment = false;
                            if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                            {
                                try
                                {
                                    CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);
                                    await hotCPMAccessKeyAgency.GetServerKeySet();
                                    while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                        await Task.Delay(50);

                                    await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();
                                    var tempConfiguration_AccessServiceResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                    if (tempConfiguration_AccessServiceResults.ComparisonResult == true)
                                    {
                                        await hotCPMAccessKeyAgency.ResetPINAttempted();
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        isEligibleAfterAssessment = true;
                                    }
                                    else
                                    {
                                        await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Model_KeysDistributionAfterPurchasex error: {ex.Message}";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                isEligibleAfterAssessment = false;
                            }

                            if (isEligibleAfterAssessment)
                            {
                                CampCommercialServer_Stripe_agency hotStripeAgency = new CampCommercialServer_Stripe_agency(tempModel_CampMember_ServiceContext);

                                Model_CampStore_StripeCheckoutSessionOTPStatus tempModel_StripeCheckoutSessionOTPStatus = await hotStripeAgency.CheckOTPSessionStatus(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_KeysDistributionAfterPurchasex.CheckoutSession);

                                bool isWithin10Minutes = (DateTime.UtcNow - tempModel_StripeCheckoutSessionOTPStatus.CreatedTimestamp).TotalMinutes <= 10;

                                if (isWithin10Minutes)
                                {
                                    CampCommercialServer_Crypto_agency hotCampCryptoAgency = new CampCommercialServer_Crypto_agency(tempModel_CampMember_ServiceContext);

                                    CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency hotBlob_Agency_CampMemberBlob = new CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency(tempModel_CampMember_ServiceContext);

                                    List<Model_CampMember_RSAServerSide_AESEncrypted>? tempListModel_RSAServerSide_AESEncrypted = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserKeysDownload();

                                    byte[] CurrentCheckOutSHA = tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_KeysDistributionAfterPurchasex.CheckoutSession;

                                    var decryptTasks = tempListModel_RSAServerSide_AESEncrypted
                                        .Where(r => r.AESEncryptedPurchaseSessionSHA?.Length > 0)
                                        .Select(async r => (await hotCampCryptoAgency.DecryptwithAES(r.AESEncryptedPurchaseSessionSHA)).SequenceEqual(CurrentCheckOutSHA))
                                        .ToList();

                                    bool[] results = await Task.WhenAll(decryptTasks);
                                    bool IsDuplicated = results.Any(r => r);

                                    if (IsDuplicated)
                                    {
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    }
                                    else
                                    {
                                        if (tempModel_StripeCheckoutSessionOTPStatus.IsPaymentRelatedWithThisAccount && tempModel_StripeCheckoutSessionOTPStatus.IsPaymentSuccesssful)
                                        {
                                            CampCommercialServer_EmailAgency hotCampMember_EmailAgency = new CampCommercialServer_EmailAgency(tempModel_CampMember_ServiceContext);

                                            CampCommercialServer_Crypto_agency hotCampCryptoKeyAgency = new CampCommercialServer_Crypto_agency(tempModel_CampMember_ServiceContext);

                                            await hotCampCryptoKeyAgency.RetriveAKey(5, null, null, null, false);

                                            List<byte[]> ListKeyName_Encrypted = new List<byte[]>();

                                            foreach (var keyPair in tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_KeysDistributionAfterPurchasex.List_Model_PairOfPurchaseKeyNameAndIndex)
                                            {
                                                byte[] encryptedData = await hotCampCryptoKeyAgency.EncryptDatawithStaticRSA(UnicodeReaderMachine.ConvertUnicodeStringToByteArray(keyPair.KeyName));
                                                ListKeyName_Encrypted.Add(encryptedData);
                                            }

                                            byte[] EncryptedCheckoutSession = await hotCampCryptoKeyAgency.EncryptDatawithStaticRSA(ByteArrayAndConversionMachine.DoComputeByteArrayToSHA256Hash(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_KeysDistributionAfterPurchasex.CheckoutSession));

                                            List<byte[]> listOfKeyName = new List<byte[]>();

                                            for (int i = 0; i < tempModel_StripeCheckoutSessionOTPStatus.QuantityThatCustomerBuy; i++)
                                            {
                                                byte[] encryptedKeyName = ListKeyName_Encrypted[i];
                                                listOfKeyName.Add(encryptedKeyName);

                                                if (tempModel_StripeCheckoutSessionOTPStatus.PricingNumber == "price_1Q6GxaEgetNpsvbV8f53yoX1")
                                                {
                                                    var generatedKey = await hotCampCryptoKeyAgency.CreateRSAKeyAndEncryptWithAES(2048, null, encryptedKeyName, EncryptedCheckoutSession);
                                                    tempListModel_RSAServerSide_AESEncrypted.Add(generatedKey);
                                                }
                                                else if (tempModel_StripeCheckoutSessionOTPStatus.PricingNumber == "price_1Q6GxoEgetNpsvbVFhDdcylW")
                                                {
                                                    var generatedKey = await hotCampCryptoKeyAgency.CreateRSAKeyAndEncryptWithAES(3072, null, encryptedKeyName, EncryptedCheckoutSession);
                                                    tempListModel_RSAServerSide_AESEncrypted.Add(generatedKey);
                                                }
                                                else if (tempModel_StripeCheckoutSessionOTPStatus.PricingNumber == "price_1Q6GxxEgetNpsvbV9nIDAScw")
                                                {
                                                    var generatedKey = await hotCampCryptoKeyAgency.CreateRSAKeyAndEncryptWithAES(4096, null, encryptedKeyName, EncryptedCheckoutSession);
                                                    tempListModel_RSAServerSide_AESEncrypted.Add(generatedKey);
                                                }
                                            }

                                            await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserKeysOverwrite(tempListModel_RSAServerSide_AESEncrypted);

                                            string userActualName = Server_UserProfileReaderMachine.Get_UserActualName(tempModel_CampMember_ServiceContext.HttpRequestx);
                                            await hotCampMember_EmailAgency.DistributeKeysToEmail(tempModel_CampMember_ServiceContext.user_Email, userActualName, listOfKeyName);

                                            tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        }
                                    }
                                }
                                else
                                {
                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                }
                            }
                        }




                        // GPT Checked 1
                        //// Dev
                        //// Read keyname from distributed Key identifier object
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_EncryptedDistributedKeyNamex != null)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Reading personal key name");

                            bool isEligibleAfterAssessment = false;
                            if (tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx != null)
                            {
                                try
                                {
                                    CampCommercialServer_AccessKey_agency hotCPMAccessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMember_ServiceContext, tempMain_CPME_Request_FromClient.Main_Configurations_FromClientx.Main_AccountAccessRecoverySet_FromClientx.Configuration_AccountRecovery_PINFromClient_Encryptedx);
                                    await hotCPMAccessKeyAgency.GetServerKeySet();
                                    while (!hotCPMAccessKeyAgency.CryptoServiceStatus)
                                        await Task.Delay(50);

                                    await hotCPMAccessKeyAgency.StartComparisonIfKeyIsMatched();
                                    var tempConfiguration_AccessServiceResults = hotCPMAccessKeyAgency.tempConfiguration_ServiceAccessResults;

                                    if (tempConfiguration_AccessServiceResults.ComparisonResult == true)
                                    {
                                        await hotCPMAccessKeyAgency.ResetPINAttempted();
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        isEligibleAfterAssessment = true;
                                    }
                                    else
                                    {
                                        await hotCPMAccessKeyAgency.LoggingPinAttemotedOrLockAccountIfExceed(tempModel_CampMember_ServiceContext.user_IdentifierSHA256);
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                        isEligibleAfterAssessment = false;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"An error occurred: {ex.Message}";
                                    isEligibleAfterAssessment = false;
                                }
                            }
                            else
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += "PIN is missing, please provide a key or contact customer service";
                                isEligibleAfterAssessment = false;
                            }

                            if (isEligibleAfterAssessment)
                            {
                                CampCommercialServer_Crypto_agency hotCampCryptoKeyAgency = new CampCommercialServer_Crypto_agency(tempModel_CampMember_ServiceContext);

                                await hotCampCryptoKeyAgency.RetriveAKey(5, null, tempMain_CPME_Request_FromClient.PublicKey, null, false);

                                byte[] tempKeyName = await hotCampCryptoKeyAgency.DecryptDatawithStaticRSA(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_EncryptedDistributedKeyNamex.KeyName);

                                Model_CampPasswordManagerEnterprise_DecryptedDistributedKeyName tempModel_DecryptedKeyName = new Model_CampPasswordManagerEnterprise_DecryptedDistributedKeyName
                                {
                                    KeyName = await hotCampCryptoKeyAgency.EncryptDatawithClientRuntimeRSA(tempKeyName)
                                };

                                tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.Model_DecryptedDistributedKeyNamex = tempModel_DecryptedKeyName;
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                            }
                            else
                            {
                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }





                        // GPT Checked 1
                        else if (tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_StripeHotPaymentsMonitoringx != null)
                        {
                            try
                            {
                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Monitoring payments");

                                CampCommercialServer_Stripe_agency hotStripeAgency = new CampCommercialServer_Stripe_agency(tempModel_CampMember_ServiceContext);

                                Model_CampStore_StripeCheckoutSessionOTPStatus tempModel_StripeCheckoutSessionOTPStatus = await hotStripeAgency.CheckOTPSessionStatus(tempMain_CPME_Request_FromClient.Main_DataModel_FromClientx.Model_StripeHotPaymentsMonitoringx.CheckoutSessionID);

                                tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.Model_StripeCheckoutSessionOTPStatusx = tempModel_StripeCheckoutSessionOTPStatus;

                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                            }
                            catch (Exception ex)
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += $"Model_StripeHotPaymentsMonitoringx error : {ex.Message}";

                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }


                    }
                    else
                    {
                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                    }






                }

                if (tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.AccountLockedFromPINLocked == true)
                {
                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Denied_ClientRequestResultToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Account locked");

                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.HotAccountStatus = UnicodeReaderMachine.ConvertUnicodeStringToByteArray("911");
                }

                MainSW.Stop();

                tempModel_CampMember_ServiceContext.ErrorMessage += $"Camp_Password_Manager_Enterprise_Service Elapse time: {MainSW.ElapsedMilliseconds} ms";

                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages += tempModel_CampMember_ServiceContext.ErrorMessage;
                await hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency.AppendCampMemberServerLogAsync(tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages);

                byte[] protobufData;
                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, tempConfiguration_CPME_ClientRequestResults);
                    protobufData = stream.ToArray();
                }



                return (protobufData, tempMain_Cache_CampPasswordManagerEnterprise);


            }
            catch (Exception ex)
            {
                Program.CampConnectServiceInstance.CampMember_SendRuntime_Error_ToSpecificConnection(tempModel_CampMember_ServiceContext.SignalIRConnectionID, "Service error");

                tempModel_CampMember_ServiceContext.ErrorMessage += $"Camp_Password_Manager_Enterprise_Service RunService error : {ex.Message}";


                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages += tempModel_CampMember_ServiceContext.ErrorMessage;
                await hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency.AppendCampMemberServerLogAsync(tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages);

                byte[] protobufData;
                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, tempConfiguration_CPME_ClientRequestResults);
                    protobufData = stream.ToArray();
                }

                return (protobufData, tempMain_Cache_CampPasswordManagerEnterprise);
            }
        }
    }
}