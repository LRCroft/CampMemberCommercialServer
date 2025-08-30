using campmember_commercial_webapp_linuximg.Models;
using CroftTeamsWinUITemplate.Models;
using CroftTeamsWinUITemplate.Services.HotAgency;
using CroftTeamsWinUITemplate.Services.Machines;
using Org.BouncyCastle.Crypto;
using ProtoBuf;
using System.Diagnostics;


using System.Security.Cryptography;


namespace campmember_commercial_webapp_linuximg.Services
{
    // 11/07/2025 CryptoAgency been reused, no independent call.
    // Use non waiting CryptoService initialization, and please use while loop outside instance. Otherwise, it'll not ready for a call.
    public class CryptoService
    {
        public bool CryptoServiceStatus = false;

        CampCommercialServer_Crypto_agency hotCampCryptoAgency;

        CampCommercialServer_Crypto_agency hotCampCryptoAgency9;

        CampCommercialServer_Crypto_agency CampCryptoAgency5;



        List<Model_CampPasswordManagerEnterprise_LandingPage_Model_EncryptedData_DecryptedFavoriteByteArray_And_GUID> tempModelList_LandingPage_EncryptedData_DecryptedFavoriteByteArray_And_GUID;

        string user_Identifier;

        bool internalIsPersonalKeyNeeded = false;

        Model_CampMember_ServiceContext tempModel_CampMemberServiceContext;

        public CryptoService(Model_CampMember_ServiceContext context, int? cryptoKeyOrder, byte[]? PersonalKey, byte[]? clientRuntimePublicKey, byte[]? severRuntimePrivateKey)
        {
            tempModel_CampMemberServiceContext = context;

            InitilizeCryptoservices(cryptoKeyOrder, PersonalKey, clientRuntimePublicKey, severRuntimePrivateKey);
        }

        // Only one function that will init these 2 together is 'ReadSpecificPassword', This need 2 Cryptoservice.
        public async Task InitilizeCryptoservices(int? cryptoKeyOrder, byte[]? PersonalKey, byte[]? clientRuntimePublicKey, byte[]? ServerRuntimePrivateKey)
        {
            if (PersonalKey != null)
            {
                internalIsPersonalKeyNeeded = true;
            }

            if (cryptoKeyOrder != null)
            {
                hotCampCryptoAgency = new CampCommercialServer_Crypto_agency(tempModel_CampMemberServiceContext);

                await hotCampCryptoAgency.RetriveAKey(cryptoKeyOrder, null, null, null, false);
            }

            if (PersonalKey != null)
            {
                hotCampCryptoAgency9 = new CampCommercialServer_Crypto_agency(tempModel_CampMemberServiceContext);

                await hotCampCryptoAgency9.RetriveAKey(null, PersonalKey, null, null, false);
            }

            if (clientRuntimePublicKey != null)
            {
                CampCryptoAgency5 = new CampCommercialServer_Crypto_agency(tempModel_CampMemberServiceContext);

                await CampCryptoAgency5.RetriveAKey(null, null, clientRuntimePublicKey, null, false);
            }

            if (ServerRuntimePrivateKey != null)
            {
                CampCryptoAgency5 = new CampCommercialServer_Crypto_agency(tempModel_CampMemberServiceContext);

                await CampCryptoAgency5.RetriveAKey(null, null, null, ServerRuntimePrivateKey, false);
            }



            CryptoServiceStatus = true;
        }




        // Seem not being used
        public async Task<byte[]?> EncryptWithCommonAgency(byte[]? data)
        {
            if (data == null || data.Length == 0)
                return null;

            while (!CryptoServiceStatus)
            {
                await Task.Delay(50);
            }
            byte[] encryptedData = await hotCampCryptoAgency.EncryptDatawithStaticRSA(data);
            return encryptedData;
        }

        // Seem not being used
        public async Task<byte[]?> DecryptWithCommonAgency(byte[]? data)
        {
            if (data == null || data.Length == 0)
                return null;

            while (!CryptoServiceStatus)
            {
                await Task.Delay(50);
            }
            byte[] decryptedData = await hotCampCryptoAgency.DecryptDatawithStaticRSA(data);
            return decryptedData;
        }

        // Seem not being used
        public async Task<byte[]?> EncryptWithSpecialAgency(byte[]? data)
        {
            if (data == null || data.Length == 0)
                return null;

            while (!CryptoServiceStatus)
            {
                await Task.Delay(50);
            }
            byte[] encryptedData = await hotCampCryptoAgency9.EncryptDatawithStaticRSA(data);
            return encryptedData;
        }

        // Seem not being used
        public async Task<byte[]?> DecryptWithSpecialAgency(byte[]? data)
        {
            if (data == null || data.Length == 0)
                return null;

            while (!CryptoServiceStatus)
            {
                await Task.Delay(50);
            }
            byte[] decryptedData = await CampCryptoAgency5.DecryptDatawithStaticRSA(data);
            return decryptedData;
        }








        // Seem not being used
        public async Task<byte[]?> EncryptWithRuntimeAgency(byte[]? data)
        {
            if (data == null || data.Length == 0)
                return null;

            while (!CryptoServiceStatus)
            {
                await Task.Delay(50);
            }
            byte[] decryptedData = await CampCryptoAgency5.EncryptDatawithClientRuntimeRSA(data);
            return decryptedData;
        }

        // Seem not being used
        public async Task<byte[]?> DecryptWithRuntimeAgency(byte[]? data)
        {
            if (data == null || data.Length == 0)
                return null;

            while (!CryptoServiceStatus)
            {
                await Task.Delay(50);
            }
            byte[] decryptedData = await CampCryptoAgency5.DecryptDatawithClientRuntimeRSA(data);
            return decryptedData;
        }




        public async Task<(CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray, CampPasswordManagerEnterprise_Configuration_Filtered_Encrypted)> AdjustmentForSendBackToClient(Configuration_CampMember_Encrypted rawfetchedFromDatabase, CPM tempCPM)
        {
            if (rawfetchedFromDatabase == null)
                return (null, null);

            var decryptionTasks = new List<Task>();
            CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray tempConfiguration_CPMUser_ByteArray = new CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray();

            async Task DecryptAndAssignAsync(CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray target, byte[] encryptedData, string fieldName)
            {
                if (encryptedData == null || encryptedData.Length == 0)
                    return;

                await DecryptAndReAssignUserConfigurationAsync(target, encryptedData, fieldName);
            }

            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.ForceCPMLoginRequirement, "ForceCPMLoginRequirement"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.LoginCPMKeyRequirement, "LoginKeyRequirement"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.SessionMinuteForHotLoginObject, "SessionMinuteForHotLoginObject"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.LoginPINRequirement, "LoginPINRequirement"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.MakeHotFavoritePINRequirement, "MakeHotFavoritePINRequirement"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.CreateNewRecordsPINRequirement, "CreateNewRecordsPINRequirement"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.ReadRecordsPINRequirement, "ReadRecordsPINRequirement"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.UpdateRecordsPINRequirement, "UpdateRecordsPINRequirement"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.CopyPasswordRecordsPINRequirement, "CopyPasswordRecordsPINRequirement"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.MoveRecordsToBinPINRequirement, "MoveRecordsToBinPINRequirement"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.RecycleBinPINRequirement, "RecycleBinPINRequirement"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.RecoverRecordPINRequirement, "RecoverRecordPINRequirement"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.PermanentDeleteRecordsPINRequirement, "PermanentDeleteRecordsPINRequirement"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.CreatedDate, "CreatedDate"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.UpdateDate, "UpdateDate"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.AccountStatus, "AccountStatus"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.DeletionDateDeclaration, "DeletionDateDeclaration"));
            decryptionTasks.Add(DecryptAndAssignAsync(tempConfiguration_CPMUser_ByteArray, rawfetchedFromDatabase.TNCPVESignedFromUser, "TNCPVESignedFromUser"));

            await Task.WhenAll(decryptionTasks);




            var tempConfiguration_Filtered_ByteArray = await EncryptConfigurationWithPublicKeyFromClient(tempConfiguration_CPMUser_ByteArray);

            return (tempConfiguration_CPMUser_ByteArray,tempConfiguration_Filtered_ByteArray);
        }





        public async Task<CampPasswordManagerEnterprise_Configuration_Filtered_Encrypted> EncryptConfigurationWithPublicKeyFromClient(CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray rawByteConfig)
        {
            var result = new CampPasswordManagerEnterprise_Configuration_Filtered_Encrypted();
            var encryptionTasks = new List<Task>();

            void EncryptFieldAsync(Func<byte[]> getter, Action<byte[]> setter)
            {
                encryptionTasks.Add(Task.Run(async () =>
                {
                    var original = getter();
                    if (original == null || original.Length == 0)
                    {
                        setter(null);
                        return;
                    }

                    try
                    {
                        var encrypted = await CampCryptoAgency5.EncryptDatawithClientRuntimeRSA(original);
                        setter(encrypted);
                    }
                    catch
                    {
                        setter(null);
                    }
                }));
            }

            if (UnicodeReaderMachine.ByteArrayToUnicodeAsync(rawByteConfig.AccountStatus) == "Default")
            {
                rawByteConfig.AccountStatus = UnicodeReaderMachine.ConvertUnicodeStringToByteArray("0");
            }
            else if (UnicodeReaderMachine.ByteArrayToUnicodeAsync(rawByteConfig.AccountStatus) == "LockedFromPINExceed")
            {
                rawByteConfig.AccountStatus = UnicodeReaderMachine.ConvertUnicodeStringToByteArray("911");
            }

            EncryptFieldAsync(() => rawByteConfig.ForceCPMLoginRequirement, x => result.ForceCPMLoginRequirement = x);
            EncryptFieldAsync(() => rawByteConfig.LoginKeyRequirement, x => result.LoginKeyRequirement = x);
            EncryptFieldAsync(() => rawByteConfig.SessionMinuteForHotLoginObject, x => result.SessionMinuteForHotLoginObject = x);
            EncryptFieldAsync(() => rawByteConfig.LoginPINRequirement, x => result.LoginPINRequirement = x);
            EncryptFieldAsync(() => rawByteConfig.MakeHotFavoritePINRequirement, x => result.MakeHotFavoritePINRequirement = x);
            EncryptFieldAsync(() => rawByteConfig.CreateNewRecordsPINRequirement, x => result.CreateNewRecordsPINRequirement = x);
            EncryptFieldAsync(() => rawByteConfig.ReadRecordsPINRequirement, x => result.ReadRecordsPINRequirement = x);
            EncryptFieldAsync(() => rawByteConfig.UpdateRecordsPINRequirement, x => result.UpdateRecordsPINRequirement = x);
            EncryptFieldAsync(() => rawByteConfig.CopyPasswordRecordsPINRequirement, x => result.CopyPasswordRecordsPINRequirement = x);
            EncryptFieldAsync(() => rawByteConfig.MoveRecordsToBinPINRequirement, x => result.MoveRecordsToBinPINRequirement = x);
            EncryptFieldAsync(() => rawByteConfig.RecycleBinPINRequirement, x => result.RecycleBinPINRequirement = x);
            EncryptFieldAsync(() => rawByteConfig.RecoverRecordPINRequirement, x => result.RecoverRecordPINRequirement = x);
            EncryptFieldAsync(() => rawByteConfig.PermanentDeleteRecordsPINRequirement, x => result.PermanentDeleteRecordsPINRequirement = x);
            EncryptFieldAsync(() => rawByteConfig.CreatedDate, x => result.CreatedDate = x);
            EncryptFieldAsync(() => rawByteConfig.UpdateDate, x => result.UpdateDate = x);
            EncryptFieldAsync(() => rawByteConfig.AccountStatus, x => result.AccountStatus = x);
            EncryptFieldAsync(() => rawByteConfig.DeletionDateDeclaration, x => result.DeletionDateDeclaration = x);
            EncryptFieldAsync(() => rawByteConfig.TNCPVESignedFromUser, x => result.TNCPVESignedFromUser = x);

            await Task.WhenAll(encryptionTasks);

            return result;
        }









        private async Task DecryptAndReAssignUserConfigurationAsync(CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray model, byte[]? encryptedValue, string type)
        {
            if (encryptedValue == null)
                return;

            byte[] decryptedValue = null;

            try
            {
                decryptedValue = await hotCampCryptoAgency.DecryptDatawithStaticRSA(encryptedValue);
            }
            catch
            {
                decryptedValue = null;
            }

            switch (type)
            {
                case "ForceCPMLoginRequirement":
                    model.ForceCPMLoginRequirement = decryptedValue;
                    break;
                case "LoginKeyRequirement":
                    model.LoginKeyRequirement = decryptedValue;
                    break;
                case "SessionMinuteForHotLoginObject":
                    model.SessionMinuteForHotLoginObject = decryptedValue;
                    break;
                case "LoginPINRequirement":
                    model.LoginPINRequirement = decryptedValue;
                    break;
                case "MakeHotFavoritePINRequirement":
                    model.MakeHotFavoritePINRequirement = decryptedValue;
                    break;
                case "CreateNewRecordsPINRequirement":
                    model.CreateNewRecordsPINRequirement = decryptedValue;
                    break;
                case "ReadRecordsPINRequirement":
                    model.ReadRecordsPINRequirement = decryptedValue;
                    break;
                case "UpdateRecordsPINRequirement":
                    model.UpdateRecordsPINRequirement = decryptedValue;
                    break;
                case "CopyPasswordRecordsPINRequirement":
                    model.CopyPasswordRecordsPINRequirement = decryptedValue;
                    break;
                case "MoveRecordsToBinPINRequirement":
                    model.MoveRecordsToBinPINRequirement = decryptedValue;
                    break;
                case "RecycleBinPINRequirement":
                    model.RecycleBinPINRequirement = decryptedValue;
                    break;
                case "RecoverRecordPINRequirement":
                    model.RecoverRecordPINRequirement = decryptedValue;
                    break;
                case "PermanentDeleteRecordsPINRequirement":
                    model.PermanentDeleteRecordsPINRequirement = decryptedValue;
                    break;
                case "CreatedDate":
                    model.CreatedDate = decryptedValue;
                    break;
                case "UpdateDate":
                    model.UpdateDate = decryptedValue;
                    break;
                case "AccountStatus":
                    if (decryptedValue != null)
                    {
                        string decoded = UnicodeReaderMachine.ByteArrayToUnicodeAsync(decryptedValue);
                        if (decoded == "Default")
                            model.AccountStatus = UnicodeReaderMachine.ConvertUnicodeStringToByteArray("0");
                        else if (decoded == "LockedFromPINExceed")
                            model.AccountStatus = UnicodeReaderMachine.ConvertUnicodeStringToByteArray("911");
                        else
                            model.AccountStatus = UnicodeReaderMachine.ConvertUnicodeStringToByteArray("999999");
                    }
                    else
                    {
                        model.AccountStatus = null;
                    }
                    break;
                case "DeletionDateDeclaration":
                    model.DeletionDateDeclaration = decryptedValue;
                    break;
                case "TNCPVESignedFromUser":
                    model.TNCPVESignedFromUser = decryptedValue ?? encryptedValue;
                    break;
                default:
                    throw new ArgumentException("Unknown type", nameof(type));
            }
        }





        public async Task<(List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray>, List<Model_CampPasswordManagerEnterprise_LandingPage_Encrypted>)> AdjustmentForSendBackToClient(List<Model_CampPasswordManagerEnterprise_LandingPage_AllMode_Encrypted_And_GUID> rawfetchedFromDatabase, int mode, bool isCallOnlyForCaching)
        {
            try
            {
                if (rawfetchedFromDatabase == null)
                {
                    return (null,null);
                }


                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST 11A");

                if (mode == 1)
                {
                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST 22A");

                    tempModelList_LandingPage_EncryptedData_DecryptedFavoriteByteArray_And_GUID = new List<Model_CampPasswordManagerEnterprise_LandingPage_Model_EncryptedData_DecryptedFavoriteByteArray_And_GUID>();
                    var favoriteDecryptionTasks = new List<Task>();

                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST 33A");

                    foreach (var item in rawfetchedFromDatabase)
                    {
                        Model_CampPasswordManagerEnterprise_LandingPage_Model_EncryptedData_DecryptedFavoriteByteArray_And_GUID tempModel_LandingPage_Mode1_EncryptedData_DecryptedFavoriteByteArray_And_GUID = new Model_CampPasswordManagerEnterprise_LandingPage_Model_EncryptedData_DecryptedFavoriteByteArray_And_GUID();

                        tempModel_LandingPage_Mode1_EncryptedData_DecryptedFavoriteByteArray_And_GUID.UniqueIdentifier = item.UniqueIdentifier;
                        tempModel_LandingPage_Mode1_EncryptedData_DecryptedFavoriteByteArray_And_GUID.ProviderName = item.ProviderName;
                        tempModel_LandingPage_Mode1_EncryptedData_DecryptedFavoriteByteArray_And_GUID.AccountName = item.AccountName;
                        tempModel_LandingPage_Mode1_EncryptedData_DecryptedFavoriteByteArray_And_GUID.RevealingCounterForAccountName = item.RevealingCounterForAccountName;
                        tempModel_LandingPage_Mode1_EncryptedData_DecryptedFavoriteByteArray_And_GUID.SpecialKeyIndicator = item.SpecialKeyIndicator;

                        favoriteDecryptionTasks.Add(DecryptAndAssignLandingPageAsync(tempModel_LandingPage_Mode1_EncryptedData_DecryptedFavoriteByteArray_And_GUID, item.FavoriteIndicator, "FavoriteIndicator"));

                        tempModelList_LandingPage_EncryptedData_DecryptedFavoriteByteArray_And_GUID.Add(tempModel_LandingPage_Mode1_EncryptedData_DecryptedFavoriteByteArray_And_GUID);
                    }

                    await Task.WhenAll(favoriteDecryptionTasks);

                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST 44A");


                    tempModelList_LandingPage_EncryptedData_DecryptedFavoriteByteArray_And_GUID.RemoveAll(item =>
                    {
                        string favoriteStr = UnicodeReaderMachine.ByteArrayToUnicodeAsync(item.FavoriteIndicator);
                        return favoriteStr != "1"; // Remove items where Favorite is not equal to "1"
                    });

                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST 55A");
                }

                dynamic preliminatedList = null;
                if (mode == 0 || mode == 2)
                {
                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST 66A");

                    preliminatedList = rawfetchedFromDatabase;

                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST 77A");
                }
                else if (mode == 1)
                {
                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST 88A");

                    preliminatedList = tempModelList_LandingPage_EncryptedData_DecryptedFavoriteByteArray_And_GUID;

                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST 99A");
                }

                var tempModel_LandingPage_ByteArrayList = new List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray>();
                var encryptionTasks = new List<Task>();
                var decryptionTasks = new List<Task>();

                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST AAAA11");

                foreach (var item in preliminatedList)
                {
                    Model_CampPasswordManagerEnterprise_LandingPage_ByteArray tempModel_LandingPage_ByteArray = new Model_CampPasswordManagerEnterprise_LandingPage_ByteArray();
                    encryptionTasks.Add(EncryptAndAssignLandingPageAsync(tempModel_LandingPage_ByteArray, item.UniqueIdentifier));

                    decryptionTasks.Add(DecryptAndAssignLandingPageAsync(tempModel_LandingPage_ByteArray, item?.ProviderName, "ProviderName"));
                    decryptionTasks.Add(DecryptAndAssignLandingPageAsync(tempModel_LandingPage_ByteArray, item?.AccountName, "AccountName"));
                    decryptionTasks.Add(DecryptAndAssignLandingPageAsync(tempModel_LandingPage_ByteArray, item?.RevealingCounterForAccountName, "RevealingCounterForAccountName"));
                    decryptionTasks.Add(DecryptAndAssignLandingPageAsync(tempModel_LandingPage_ByteArray, item?.SpecialKeyIndicator, "SpecialKeyIndicator"));

                    if (mode == 0 || mode == 2)
                    {
                        decryptionTasks.Add(DecryptAndAssignLandingPageAsync(tempModel_LandingPage_ByteArray, item?.FavoriteIndicator, "FavoriteIndicator"));
                    }
                    if (mode == 1)
                    {
                        tempModel_LandingPage_ByteArray.FavoriteIndicator = item.FavoriteIndicator;
                    }
                    if (mode == 2)
                    {
                        tempModel_LandingPage_ByteArray.DeletionCall = item.DeletionCall;
                    }

                    tempModel_LandingPage_ByteArrayList.Add(tempModel_LandingPage_ByteArray);
                }

                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST AAAA22");

                await Task.WhenAll(encryptionTasks.Concat(decryptionTasks));


                int dsfds = tempModel_LandingPage_ByteArrayList.Count;

                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $" tempModel_LandingPage_ByteArrayList Count {dsfds}");

                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST AAAA33");



                if(isCallOnlyForCaching)
                {
                    return (tempModel_LandingPage_ByteArrayList, null);
                }
                else
                {
                    List<Model_CampPasswordManagerEnterprise_LandingPage_Encrypted> tempListModel_LandingPage_ByteArray = await EncryptLandingPageWithPublicKeyFromClient(tempModel_LandingPage_ByteArrayList);

                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST AAAA44");

                    return (tempModel_LandingPage_ByteArrayList, tempListModel_LandingPage_ByteArray);
                }
            }
            catch (Exception ex)
            {
                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"ERROR Adjust  {ex.Message}");

                tempModel_CampMemberServiceContext.ErrorMessage += $"CryptoService AdjustmentForSendBackToClient error : {ex}";

                return (null, null);
            }
        }




        public async Task<int> CountFavoriteRecords(List<Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID> records)
        {
            var tasks = new List<Task>();
            var tempList = new List<Model_CampPasswordManagerEnterprise_LandingPage_Model_EncryptedData_DecryptedFavoriteByteArray_And_GUID>();

            foreach (var item in records)
            {
                var tempModel = new Model_CampPasswordManagerEnterprise_LandingPage_Model_EncryptedData_DecryptedFavoriteByteArray_And_GUID();
                tempList.Add(tempModel);
                tasks.Add(DecryptAndAssignLandingPageAsync(tempModel, item.FavoriteIndicator, "FavoriteIndicator"));
            }

            await Task.WhenAll(tasks);

            return tempList.Count(x => x.FavoriteIndicator != null && UnicodeReaderMachine.ByteArrayToUnicodeAsync(x.FavoriteIndicator) == "1");
        }






        public async Task<List<Model_CampPasswordManagerEnterprise_LandingPage_Encrypted>> EncryptLandingPageWithPublicKeyFromClient(List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray> ListLandingPage)
        {
            try
            {
                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST BBBB11");

                var encryptedList = new List<Model_CampPasswordManagerEnterprise_LandingPage_Encrypted>();
                var encryptionTasks = new List<Task>();

                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST BBBB22");

                foreach (var item in ListLandingPage)
                {
                    var encryptedItem = new Model_CampPasswordManagerEnterprise_LandingPage_Encrypted();
                    var capturedItem = item; // capture loop variable

                    void EncryptFieldAsync(byte[]? source, Action<byte[]> setter, string fieldName)
                    {
                        encryptionTasks.Add(Task.Run(async () =>
                        {
                            try
                            {
                                var idString = capturedItem.UniqueIdentifier != null
                                    ? Convert.ToBase64String(capturedItem.UniqueIdentifier)
                                    : "null";

                                if (source == null || source.Length == 0)
                                {
                                    setter(null);
                                }

                                var encrypted = await CampCryptoAgency5.EncryptDatawithClientRuntimeRSA(source);
                                setter(encrypted);
                            }
                            catch (Exception ex)
                            {
                                var idString = capturedItem.UniqueIdentifier != null
                                    ? Convert.ToBase64String(capturedItem.UniqueIdentifier)
                                    : "null";

                                setter(null);
                            }
                        }));
                    }

                    encryptedItem.UniqueIdentifier = capturedItem.UniqueIdentifier;

                    var providerName = capturedItem.ProviderName;
                    if (providerName != null && providerName.Length > 0)
                        EncryptFieldAsync(providerName, x => encryptedItem.ProviderName = x, nameof(capturedItem.ProviderName));

                    var accountName = capturedItem.AccountName;
                    if (accountName != null && accountName.Length > 0)
                        EncryptFieldAsync(accountName, x => encryptedItem.AccountName = x, nameof(capturedItem.AccountName));

                    var revealingCounter = capturedItem.RevealingCounterForAccountName;
                    if (revealingCounter != null && revealingCounter.Length > 0)
                        EncryptFieldAsync(revealingCounter, x => encryptedItem.RevealingCounterForAccountName = x, nameof(capturedItem.RevealingCounterForAccountName));

                    var specialKey = capturedItem.SpecialKeyIndicator;
                    if (specialKey != null && specialKey.Length > 0)
                        EncryptFieldAsync(specialKey, x => encryptedItem.SpecialKeyIndicator = x, nameof(capturedItem.SpecialKeyIndicator));

                    var favorite = capturedItem.FavoriteIndicator;
                    if (favorite != null && favorite.Length > 0)
                        EncryptFieldAsync(favorite, x => encryptedItem.FavoriteIndicator = x, nameof(capturedItem.FavoriteIndicator));

                    if (capturedItem.DeletionCall.HasValue)
                        encryptedItem.DeletionCall = capturedItem.DeletionCall;

                    encryptedList.Add(encryptedItem);
                }


                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST BBBB33");

                await Task.WhenAll(encryptionTasks);

                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"TEST BBBB44");

                return encryptedList;
            }
            catch (Exception ex)
            {
                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceContext.SignalIRConnectionID, $"EncryptLandingPageWithPublicKeyFromClient Error  {ex.Message}");

                return null;
            }

        }






        public async Task<Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray> AdjustmentForSendBackToClient(Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID rawfetchedFromDatabase)
        {
            if (rawfetchedFromDatabase == null)
            {
                return null;
            }

            var TempSpecificRecord_ByteArray = new Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray();
            var encryptionTasks = new List<Task>();
            var decryptionTasks = new List<Task>();

            encryptionTasks.Add(EncryptAndAssignLandingPageAsync(TempSpecificRecord_ByteArray, rawfetchedFromDatabase.UniqueIdentifier));

            decryptionTasks.Add(DecryptAndAssignLandingPageAsync(TempSpecificRecord_ByteArray, rawfetchedFromDatabase.ProviderName, "ProviderName"));
            decryptionTasks.Add(DecryptAndAssignLandingPageAsync(TempSpecificRecord_ByteArray, rawfetchedFromDatabase.AccountName, "AccountName"));
            decryptionTasks.Add(DecryptAndAssignLandingPageAsync(TempSpecificRecord_ByteArray, rawfetchedFromDatabase.RevealingCounterForAccountName, "RevealingCounterForAccountName"));
            decryptionTasks.Add(DecryptAndAssignLandingPageAsync(TempSpecificRecord_ByteArray, rawfetchedFromDatabase.SpecialKeyIndicator, "SpecialKeyIndicator"));
            decryptionTasks.Add(DecryptAndAssignLandingPageAsync(TempSpecificRecord_ByteArray, rawfetchedFromDatabase.FavoriteIndicator, "FavoriteIndicator"));

            if (internalIsPersonalKeyNeeded)
            {
                decryptionTasks.Add(DecryptWithPersonalKeyAndAssignLandingPageAsync(TempSpecificRecord_ByteArray, rawfetchedFromDatabase.ProviderURL, "ProviderURL"));
                decryptionTasks.Add(DecryptWithPersonalKeyAndAssignLandingPageAsync(TempSpecificRecord_ByteArray, rawfetchedFromDatabase.CreatedDate, "CreatedDate"));
                decryptionTasks.Add(DecryptWithPersonalKeyAndAssignLandingPageAsync(TempSpecificRecord_ByteArray, rawfetchedFromDatabase.UpdatedDate, "UpdatedDate"));
                decryptionTasks.Add(DecryptWithPersonalKeyAndAssignLandingPageAsync(TempSpecificRecord_ByteArray, rawfetchedFromDatabase.LastPasswordCall, "LastPasswordCall"));
            }
            else
            {
                decryptionTasks.Add(DecryptAndAssignLandingPageAsync(TempSpecificRecord_ByteArray, rawfetchedFromDatabase.ProviderURL, "ProviderURL"));
                decryptionTasks.Add(DecryptAndAssignLandingPageAsync(TempSpecificRecord_ByteArray, rawfetchedFromDatabase.CreatedDate, "CreatedDate"));
                decryptionTasks.Add(DecryptAndAssignLandingPageAsync(TempSpecificRecord_ByteArray, rawfetchedFromDatabase.UpdatedDate, "UpdatedDate"));
                decryptionTasks.Add(DecryptAndAssignLandingPageAsync(TempSpecificRecord_ByteArray, rawfetchedFromDatabase.LastPasswordCall, "LastPasswordCall"));
            }

            await Task.WhenAll(encryptionTasks.Concat(decryptionTasks));


            Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray tempModel_SpecificRecord_ByteArray = await EncryptSpecificRecordsWithPublicKeyFromClient(TempSpecificRecord_ByteArray);


            return tempModel_SpecificRecord_ByteArray;
        }








        public async Task<Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray> EncryptSpecificRecordsWithPublicKeyFromClient(Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray data)
        {
            var encrypted = new Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray();

            async Task<byte[]?> EncryptIfNotNull(byte[]? source, string fieldName)
            {
                if (CampCryptoAgency5 == null)
                {
                    Debug.WriteLine($"[Encryption Error] CampCryptoAgency5 instance is null. Cannot encrypt field: {fieldName}");
                    throw new NullReferenceException("CampCryptoAgency5 instance is null");
                }

                if (source == null || source.Length == 0)
                {
                    Debug.WriteLine($"[Encryption Skipped] Field: {fieldName}, source is null or empty.");
                    return null;
                }

                try
                {
                    Debug.WriteLine($"[Encryption Start] Field: {fieldName}, Length: {source.Length}");
                    var encryptedData = await CampCryptoAgency5.EncryptDatawithClientRuntimeRSA(source);
                    Debug.WriteLine($"[Encryption Success] Field: {fieldName}, Encrypted Length: {encryptedData?.Length}");
                    return encryptedData;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[Encryption Error] Field: {fieldName}, Length: {source.Length}, Exception: {ex}");
                    throw;
                }
            }

            var tasks = new List<Task>
    {
        Task.Run(async () => encrypted.ProviderName = await EncryptIfNotNull(data.ProviderName, nameof(data.ProviderName))),
        Task.Run(async () => encrypted.ProviderURL = await EncryptIfNotNull(data.ProviderURL, nameof(data.ProviderURL))),
        Task.Run(async () => encrypted.AccountName = await EncryptIfNotNull(data.AccountName, nameof(data.AccountName))),
        Task.Run(async () => encrypted.RevealingCounterForAccountName = await EncryptIfNotNull(data.RevealingCounterForAccountName, nameof(data.RevealingCounterForAccountName))),
        Task.Run(async () => encrypted.SpecialKeyIndicator = await EncryptIfNotNull(data.SpecialKeyIndicator, nameof(data.SpecialKeyIndicator))),
        Task.Run(async () => encrypted.FavoriteIndicator = await EncryptIfNotNull(data.FavoriteIndicator, nameof(data.FavoriteIndicator))),
        Task.Run(async () => encrypted.CreatedDate = await EncryptIfNotNull(data.CreatedDate, nameof(data.CreatedDate))),
        Task.Run(async () => encrypted.UpdatedDate = await EncryptIfNotNull(data.UpdatedDate, nameof(data.UpdatedDate))),
        Task.Run(async () => encrypted.LastPasswordCall = await EncryptIfNotNull(data.LastPasswordCall, nameof(data.LastPasswordCall))),
    };

            encrypted.UniqueIdentifier = data.UniqueIdentifier; // assign as-is

            await Task.WhenAll(tasks);

            return encrypted;
        }




        public async Task<Model_CampPasswordManagerEnterprise_JustPassword_ByteArray> AdjustmentForSendBackToClient(Model_CampPasswordManagerEnterprise_JustPassword_Encrypted rawfetchedFromDatabase, bool isRuntimeEncryptionNeed)
        {
            if (rawfetchedFromDatabase == null)
            {
                return null;
            }

            Model_CampPasswordManagerEnterprise_JustPassword_ByteArray tempModel_JustPassword = new Model_CampPasswordManagerEnterprise_JustPassword_ByteArray();

            if (internalIsPersonalKeyNeeded)
            {
                tempModel_JustPassword.Password = await DecryptWithSpecialAgency(rawfetchedFromDatabase.Password);
            }
            else
            {
                tempModel_JustPassword.Password = await DecryptWithCommonAgency(rawfetchedFromDatabase.Password);
            }



            if(isRuntimeEncryptionNeed)
            {

                Model_CampPasswordManagerEnterprise_JustPassword_ByteArray tempModel_JustPassword_ByteArray = await EncryptSpecificPasswordWithPublicKeyFromClient(tempModel_JustPassword);

                return tempModel_JustPassword_ByteArray;
            }
            else
            {
                return tempModel_JustPassword;
            }
        }








        public async Task<Model_CampPasswordManagerEnterprise_JustPassword_ByteArray> AdjustmentForSendBackToClient(Model_CampPasswordManagerEnterprise_CachePassword cachePassword)
        {

            Model_CampPasswordManagerEnterprise_JustPassword_ByteArray tempModel_JustPassword = new Model_CampPasswordManagerEnterprise_JustPassword_ByteArray()
            {
                Password = cachePassword.password
            };

            Model_CampPasswordManagerEnterprise_JustPassword_ByteArray tempModel_JustPassword_ByteArray = await EncryptSpecificPasswordWithPublicKeyFromClient(tempModel_JustPassword);

            return tempModel_JustPassword_ByteArray;
        }




        public async Task<Model_CampPasswordManagerEnterprise_JustPassword_ByteArray> EncryptSpecificPasswordWithPublicKeyFromClient(Model_CampPasswordManagerEnterprise_JustPassword_ByteArray data)
        {
            var encrypted = new Model_CampPasswordManagerEnterprise_JustPassword_ByteArray();

            async Task<byte[]?> EncryptIfNotNull(byte[]? source, string fieldName)
            {
                if (source == null || source.Length == 0)
                {
                    Debug.WriteLine($"[Encryption Skipped] Field: {fieldName}, source is null or empty.");
                    return null;
                }

                try
                {
                    Debug.WriteLine($"[Encryption Start] Field: {fieldName}, Length: {source.Length}");
                    var encryptedData = await CampCryptoAgency5.EncryptDatawithClientRuntimeRSA(source);
                    Debug.WriteLine($"[Encryption Success] Field: {fieldName}, Encrypted Length: {encryptedData?.Length}");
                    return encryptedData;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[Encryption Error] Field: {fieldName}, Length: {source.Length}, Exception: {ex}");
                    throw;
                }
            }

            encrypted.Password = await EncryptIfNotNull(data.Password, nameof(data.Password));

            return encrypted;
        }








        private async Task DecryptAndAssignLandingPageAsync(dynamic model, byte[]? encryptedValue, string type)
        {
            if (encryptedValue == null) return;

            var decryptedValue = await hotCampCryptoAgency.DecryptDatawithStaticRSA(encryptedValue);

            switch (type)
            {
                case "ProviderName":
                    model.ProviderName = decryptedValue;
                    break;
                case "ProviderURL":
                    model.ProviderURL = decryptedValue;
                    break;
                case "AccountName":
                    model.AccountName = decryptedValue;
                    break;
                case "RevealingCounterForAccountName":
                    model.RevealingCounterForAccountName = decryptedValue;
                    break;
                case "SpecialKeyIndicator":
                    model.SpecialKeyIndicator = decryptedValue;
                    break;
                case "FavoriteIndicator":
                    model.FavoriteIndicator = decryptedValue;
                    break;
                case "CreatedDate":
                    model.CreatedDate = decryptedValue;
                    break;
                case "UpdatedDate":
                    model.UpdatedDate = decryptedValue;
                    break;
                case "LastPasswordCall":
                    model.LastPasswordCall = decryptedValue;
                    break;
            }
        }

        private async Task DecryptWithPersonalKeyAndAssignLandingPageAsync(dynamic model, byte[]? encryptedValue, string type)
        {
            if (encryptedValue == null) return;

            var decryptedValue = await hotCampCryptoAgency9.DecryptDatawithStaticRSA(encryptedValue);

            switch (type)
            {
                case "ProviderName":
                    model.ProviderName = decryptedValue;
                    break;
                case "ProviderURL":
                    model.ProviderURL = decryptedValue;
                    break;
                case "AccountName":
                    model.AccountName = decryptedValue;
                    break;
                case "RevealingCounterForAccountName":
                    model.RevealingCounterForAccountName = decryptedValue;
                    break;
                case "SpecialKeyIndicator":
                    model.SpecialKeyIndicator = decryptedValue;
                    break;
                case "FavoriteIndicator":
                    model.FavoriteIndicator = decryptedValue;
                    break;
                case "CreatedDate":
                    model.CreatedDate = decryptedValue;
                    break;
                case "UpdatedDate":
                    model.UpdatedDate = decryptedValue;
                    break;
                case "LastPasswordCall":
                    model.LastPasswordCall = decryptedValue;
                    break;
            }
        }



        // GUID always with key number 2
        private async Task EncryptAndAssignLandingPageAsync(dynamic model, Guid uniqueIdentifier)
        {
            while (!CryptoServiceStatus)
            {
                await Task.Delay(50);
            }

            var encryptedValue = await hotCampCryptoAgency.EncryptDatawithStaticRSA(UnicodeReaderMachine.ConvertGuidToByteArray(uniqueIdentifier));
            model.UniqueIdentifier = encryptedValue;
        }








        public async Task<Model_CampMember_NecessaryKey_Encrypted> AdjustmentForSendBackToClient(Model_CampMember_NecessaryKey_ByteArray data)
        {
            while (!CryptoServiceStatus)
                await Task.Delay(50);

            // 1️⃣ Generate a random AES key and IV
            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.GenerateKey();
            aes.GenerateIV();

            // 2️⃣ Encrypt exponent and modulus with AES
            byte[] encryptedExponent, encryptedModulus;
            using (var encryptor = aes.CreateEncryptor())
            {
                encryptedExponent = encryptor.TransformFinalBlock(data.exponent, 0, data.exponent.Length);
                encryptedModulus = encryptor.TransformFinalBlock(data.modulus, 0, data.modulus.Length);
            }

            // 3️⃣ Combine AES key + IV to encrypt with RSA
            byte[] aesKeyWithIV = aes.Key.Concat(aes.IV).ToArray();
            byte[] encryptedAES = await CampCryptoAgency5.EncryptDatawithClientRuntimeRSA(aesKeyWithIV);

            // 4️⃣ Build the model
            return new Model_CampMember_NecessaryKey_Encrypted
            {
                Encryptedexponent = encryptedExponent,
                Encryptedmodulus = encryptedModulus,
                KeyOrder = data.KeyOrder,
                UserIdentifierSHA = data.UserIdentifierSHA,
                EncryptedAES = encryptedAES
            };
        }





    }
}