using Azure;
using campmember_commercial_webapp_linuximg.Models;
using campmember_commercial_webapp_linuximg.Services.HotAgency;
using CroftTeamsWinUITemplate.Models;
using CroftTeamsWinUITemplate.Services.HotAgency;
using CroftTeamsWinUITemplate.Services.Machines;
using Microsoft.AspNetCore.Mvc;
using ProtoBuf;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;

namespace campmember_commercial_webapp_linuximg.Services
{
    public class CampMember_Automatic_Recover_User_Account_Service
    {
        Model_CampMember_ServiceContext tempModel_CampMemberServiceContext;
        Model_CampMember_ProgramIdentification tempModel_ProgramIdentification;
        Configuration_Global_CampMember_ClientRequestResults tempConfiguration_Global_CampMember_ClientRequestResults;

        CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency;
        CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency;
        CampCommercialServer_OracleObjectStorage_agency hotOracle_Object_Storage_Agency;
        CampCommercialServer_BucketInMachine hotCampCommercialServerBucketMachine;

        public CampMember_Automatic_Recover_User_Account_Service(Model_CampMember_ServiceContext tempModel_CampMember_ServiceContext, Model_CampMember_ProgramIdentification data)
        {
            tempModel_CampMemberServiceContext = tempModel_CampMember_ServiceContext;
            tempModel_ProgramIdentification = data;

            tempConfiguration_Global_CampMember_ClientRequestResults = new Configuration_Global_CampMember_ClientRequestResults()
            {
                Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult
                {

                },
                Main_Global_CampMember_DataModel_FromServerx = new Main_Global_CampMember_DataModel_FromServer
                {

                },

                JobID = tempModel_ProgramIdentification.JobID

            };

            hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency = new CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency(tempModel_CampMember_ServiceContext);
            hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency = new CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency(tempModel_CampMember_ServiceContext);
            hotOracle_Object_Storage_Agency = new CampCommercialServer_OracleObjectStorage_agency(tempModel_CampMember_ServiceContext);
            hotCampCommercialServerBucketMachine = new CampCommercialServer_BucketInMachine(tempModel_CampMember_ServiceContext);

        }

        // Rearranged version with clear stopwatch sections
        public async Task<byte[]> RecoverRequest()
        {
            try
            {
                var MainSW = Stopwatch.StartNew();

                tempModel_CampMemberServiceContext.ErrorMessage += "Start service:\n";

                string dfsdf = tempModel_ProgramIdentification.JobID.ToString();

                tempModel_CampMemberServiceContext.ErrorMessage += $"GUID from client : {dfsdf}";

                var swTotal = Stopwatch.StartNew();

                var swKeys = Stopwatch.StartNew();

                CampCommercialServer_Crypto_agency hotCampCryptoKeyAgency0 = new CampCommercialServer_Crypto_agency(tempModel_CampMemberServiceContext);



                bool? ifUserKeysExisted = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserKeysCheckExistance();

                tempModel_CampMemberServiceContext.ErrorMessage += "Checked user key existence\n";

                if (ifUserKeysExisted == false)
                {
                    var tasks = new List<Task<Model_CampMember_RSAServerSide_AESEncrypted>>
                    {
                        // Camp User Config
                        hotCampCryptoKeyAgency0.CreateRSAKeyAndEncryptWithAES(4096, 1, null, null),

                        // Camp Password Manager
                        hotCampCryptoKeyAgency0.CreateRSAKeyAndEncryptWithAES(4096, 2, null, null),

                        // Camp Dating
                        hotCampCryptoKeyAgency0.CreateRSAKeyAndEncryptWithAES(4096, 3, null, null),

                        // Camp Worthwhile
                        hotCampCryptoKeyAgency0.CreateRSAKeyAndEncryptWithAES(4096, 4, null, null),

                        // CPME Special Encryption
                        hotCampCryptoKeyAgency0.CreateRSAKeyAndEncryptWithAES(4096, 5, null, null),
                        hotCampCryptoKeyAgency0.CreateRSAKeyAndEncryptWithAES(4096, 6, null, null),
                        hotCampCryptoKeyAgency0.CreateRSAKeyAndEncryptWithAES(4096, 7, null, null),
                        hotCampCryptoKeyAgency0.CreateRSAKeyAndEncryptWithAES(4096, 8, null, null),
                        hotCampCryptoKeyAgency0.CreateRSAKeyAndEncryptWithAES(4096, 9, null, null),
                        hotCampCryptoKeyAgency0.CreateRSAKeyAndEncryptWithAES(4096, 10, null, null),

                    };

                    Model_CampMember_RSAServerSide_AESEncrypted[] results = await Task.WhenAll(tasks);

                    await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserKeysOverwrite(results.ToList());
                }







                swKeys.Stop();
                tempModel_CampMemberServiceContext.ErrorMessage += $"[Time] Key Check/Generation: {swKeys.Elapsed.TotalSeconds:0.00}s\n";

                var swStripe = Stopwatch.StartNew();
                CampCommercialServer_Stripe_agency hotStripeAgency = new CampCommercialServer_Stripe_agency(tempModel_CampMemberServiceContext);
                hotStripeAgency.RobustnessAccountReadinessMaker();
                swStripe.Stop();
                tempModel_CampMemberServiceContext.ErrorMessage += $"[Time] Stripe Ready: {swStripe.Elapsed.TotalSeconds:0.00}s\n";








                var swAccMgr = Stopwatch.StartNew();

                CampCommercialServer_Account_Manager_agency hotCampMember_Account_Manager_Agency = new CampCommercialServer_Account_Manager_agency(tempModel_CampMemberServiceContext);
                await hotCampMember_Account_Manager_Agency.CheckWithAutomaticRecoverUser();






                swAccMgr.Stop();
                tempModel_CampMemberServiceContext.ErrorMessage += $"[Time] Account Recovery Check: {swAccMgr.Elapsed.TotalSeconds:0.00}s\n";

                var swCrypto = Stopwatch.StartNew();
                CryptoService hotCryptoService = new CryptoService(tempModel_CampMemberServiceContext, 1, null, tempModel_ProgramIdentification.PublicKey, null);

                swCrypto.Stop();
                tempModel_CampMemberServiceContext.ErrorMessage += $"[Time] CryptoService Ready: {swCrypto.Elapsed.TotalSeconds:0.00}s\n";








                bool? IsUserDefinedFixLocation = await hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency.IsUserLatitudeDefinedAsync();

                if(IsUserDefinedFixLocation == true)
                {
                    tempConfiguration_Global_CampMember_ClientRequestResults.Configuration_CampMember_ServiceResultx.isCDTProfileBeenSetup = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                }
                else if(IsUserDefinedFixLocation == false)
                {
                    tempConfiguration_Global_CampMember_ClientRequestResults.Configuration_CampMember_ServiceResultx.isCDTProfileBeenSetup = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                }
                else
                {

                }






                if (tempModel_ProgramIdentification.CPMx != null)
                {
                    Task<CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray> adjustmentTask = null;


                    var subscriptionTask = hotStripeAgency.GetFirstActiveSubscriptionDetails();
                    var lifetimeTask = hotStripeAgency.IfLifetimePurchaseExistedThenGetFirstFoundedPurchaseDetails();




                    if (tempModel_CampMemberServiceContext.Model_AccountAgencyConsultResultsx.ActualUserConfigurationEncrypted == null)
                    {
                        CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray tempCampPasswordManagerEnterprise_Configuration_Filtered_ByteArray = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserConfigCacheDownload();

                        while (!hotCryptoService.CryptoServiceStatus)
                        {
                            await Task.Delay(50);
                        }

                        tempConfiguration_Global_CampMember_ClientRequestResults.Main_Global_CampMember_DataModel_FromServerx.CampMember_Configuration_Filtered_Encryptedx = await hotCryptoService.EncryptConfigurationWithPublicKeyFromClient(tempCampPasswordManagerEnterprise_Configuration_Filtered_ByteArray);

                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"Assign cache");
                    }
                    else
                    {
                        (CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray tempCampPasswordManagerEnterprise_Configuration_Filtered_ByteArray, tempConfiguration_Global_CampMember_ClientRequestResults.Main_Global_CampMember_DataModel_FromServerx.CampMember_Configuration_Filtered_Encryptedx) = await hotCryptoService.AdjustmentForSendBackToClient(tempModel_CampMemberServiceContext.Model_AccountAgencyConsultResultsx.ActualUserConfigurationEncrypted, tempModel_ProgramIdentification.CPMx);

                        await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserConfigCacheOverwrite(tempCampPasswordManagerEnterprise_Configuration_Filtered_ByteArray);
                    }




                    if (tempConfiguration_Global_CampMember_ClientRequestResults.Main_Global_CampMember_DataModel_FromServerx.CampMember_Configuration_Filtered_Encryptedx != null)
                    {
                        while (!hotCryptoService.CryptoServiceStatus)
                        {
                            await Task.Delay(50);
                        }

                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"Start runtime encryption");



                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"Finished");
                    }
                    else
                    {

                    }







                    await Task.WhenAll(subscriptionTask, lifetimeTask);

                    var subscriptionResult = subscriptionTask.Result;

                    var lifetimeResult = lifetimeTask.Result;

                    if (subscriptionResult != null)
                    {
                        tempConfiguration_Global_CampMember_ClientRequestResults.Main_Global_CampMember_DataModel_FromServerx.CampMember_Configuration_Filtered_Encryptedx.PaymentSubscription = new Model_CampStore_StripePayments
                        {
                            Subscriptions_ByteArray = subscriptionResult
                        };
                    }
                    else if (lifetimeResult != null)
                    {
                        lifetimeResult.NewsFromDevelopers = UnicodeReaderMachine.ConvertUnicodeStringToByteArray("Kickstart fundings gathering");

                        tempConfiguration_Global_CampMember_ClientRequestResults.Main_Global_CampMember_DataModel_FromServerx.CampMember_Configuration_Filtered_Encryptedx.PaymentSubscription = new Model_CampStore_StripePayments
                        {
                            Configuration_LifetimePurchase_ByteArrayx = lifetimeResult
                        };
                    }

                    var keysTask = hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserKeysDownload();

                    var cdtCheckTask = hotCampCommercialServerBucketMachine.CDTProfileCheckExistance(tempModel_CampMemberServiceContext.user_IdentifierSHAHEX);

                    await Task.WhenAll(keysTask, cdtCheckTask);

                    var keyList = keysTask.Result;

                    tempModel_CampMemberServiceContext.ErrorMessage += $"User has keys in total of {keyList.Count} keys.";

                    bool? cdtExists = cdtCheckTask.Result;

                    tempConfiguration_Global_CampMember_ClientRequestResults.Configuration_CampMember_ServiceResultx.isCDTProfileBeenSetup = ByteArrayAndConversionMachine.ConvertBoolToByteArray(cdtExists == true);

                    tempConfiguration_Global_CampMember_ClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages += tempModel_CampMemberServiceContext.ErrorMessage;

                    var swSer = Stopwatch.StartNew();

                    byte[] protobufData0 = null;
                    using (var stream = new MemoryStream())
                    {
                        Serializer.Serialize(stream, tempConfiguration_Global_CampMember_ClientRequestResults);
                        protobufData0 = stream.ToArray();
                    }

                    return protobufData0;
                }










                MainSW.Stop();

                tempModel_CampMemberServiceContext.ErrorMessage += $"CampMember_Automatic_Recover_User_Account_Service Elapse time: {MainSW.ElapsedMilliseconds} ms";

                await hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency.AppendCampMemberServerLogAsync(tempModel_CampMemberServiceContext.ErrorMessage);

                byte[] protobufData1 = null;
                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, tempConfiguration_Global_CampMember_ClientRequestResults);
                    protobufData1 = stream.ToArray();
                }

                return protobufData1;





            }
            catch (Exception ex)
            {
                tempModel_CampMemberServiceContext.ErrorMessage += $"CampMember_Automatic_Recover_User_Account_Service RunService error : {ex.Message}";
                tempConfiguration_Global_CampMember_ClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages = tempModel_CampMemberServiceContext.ErrorMessage;

                await hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency.AppendCampMemberServerLogAsync(tempModel_CampMemberServiceContext.ErrorMessage);

                byte[] protobufData = null;
                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, tempConfiguration_Global_CampMember_ClientRequestResults);
                    protobufData = stream.ToArray();
                }

                return protobufData;
            }
        }

    }




}
