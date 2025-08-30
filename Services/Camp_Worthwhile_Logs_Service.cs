using campmember_commercial_webapp_linuximg.Services.HotAgency;
using CroftTeamsWinUITemplate.Models;
using CroftTeamsWinUITemplate.Services.HotAgency;
using CroftTeamsWinUITemplate.Services.Machines;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Ocsp;
using ProtoBuf;
using System.Diagnostics;

namespace campmember_commercial_webapp_linuximg.Services
{
    public class Camp_Worthwhile_Logs_Service
    {
        Model_CampMember_ServiceContext tempModel_CampMember_ServiceContext;
        Main_CampWorthwhileLogs_Request_FromClient tempMain_CWWRequest_FromClient;
        Configuration_CampWorthwhileLogs_ClientRequestResults tempConfiguration_CWWClientRequestResults;


        CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency;

        public Camp_Worthwhile_Logs_Service(Model_CampMember_ServiceContext context, Main_CampWorthwhileLogs_Request_FromClient data)
        {
            tempModel_CampMember_ServiceContext = context;
            tempMain_CWWRequest_FromClient = data;

            tempConfiguration_CWWClientRequestResults = new Configuration_CampWorthwhileLogs_ClientRequestResults
            {
                Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult()
                {

                },

                Main_CWW_DataModel_FromServerx = new Main_CampWorthwhileLogs_DataModel_FromServer()
                {

                },

                JobID = tempMain_CWWRequest_FromClient.JobID,
            };

            hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency = new CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency(tempModel_CampMember_ServiceContext);
        }



        public async Task<byte[]> RunService()
        {
            try
            {

                var MainSW = Stopwatch.StartNew();



                CampMember_Account_Manager_Agenc_Old hotCampMember_Account_Manager_Agency = new CampMember_Account_Manager_Agenc_Old(tempModel_CampMember_ServiceContext);
                while (!hotCampMember_Account_Manager_Agency.CryptoServiceStatus)
                {
                    await Task.Delay(50);
                }

                tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx = await hotCampMember_Account_Manager_Agency.IfAccountCannotReceiveAService();









                CampCommercialServer_OracleObjectStorage_agency hotOracle_Object_Storage_Agency = new CampCommercialServer_OracleObjectStorage_agency(tempModel_CampMember_ServiceContext);

                try
                {
                    // BLOB
                    if (tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_InserOrUpdateRecordsAndLogsx != null)
                    {
                        CryptoService hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 4, null, null, null);

                        Model_CampWorthwhileLogs_Records? tempModel_CWW_Records = await hotOracle_Object_Storage_Agency.CWWRecordsDownload();

                        if (tempModel_CWW_Records?.ListModel_CWW_RTF_Records == null)
                        {
                            tempModel_CampMember_ServiceContext.ErrorMessage += $"LIST LOST IS NULL";

                            tempModel_CWW_Records = new Model_CampWorthwhileLogs_Records()
                            {
                                ListModel_CWW_RTF_Records = new List<Model_CampWorthwhileLogs_RTF_Records>()
                            };
                        }

                        if (tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_InserOrUpdateRecordsAndLogsx.Content == null)
                        {
                            tempModel_CampMember_ServiceContext.ErrorMessage += $"Null content INTO";

                            Guid targetRecordsID0;
                            if (tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_InserOrUpdateRecordsAndLogsx.EncryptedGUID != null)
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += $"Received Encrypted GUID";


                                while (!hotCryptoService.CryptoServiceStatus)
                                {
                                    await Task.Delay(50);
                                }

                                targetRecordsID0 = UnicodeReaderMachine.ConvertByteArrayToGuid(
                                    await hotCryptoService.DecryptWithCommonAgency(
                                        tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_InserOrUpdateRecordsAndLogsx.EncryptedGUID));

                                tempModel_CampMember_ServiceContext.ErrorMessage += $"READ ENCRYPTGUID:::";

                                // Decrypt all existing record GUIDs in parallel
                                var decryptTasks = tempModel_CWW_Records.ListModel_CWW_RTF_Records
                                    .Select(async r => new
                                    {
                                        Record = r,
                                        DecryptedGuid = UnicodeReaderMachine.ConvertByteArrayToGuid(
                                            await hotCryptoService.DecryptWithCommonAgency(r.RSAEncryptedUniqueIdentifier))
                                    }).ToList();

                                var decryptedResults = await Task.WhenAll(decryptTasks);

                                tempModel_CampMember_ServiceContext.ErrorMessage += $"Decryption Done:::";

                                var itemToRemove = decryptedResults
                                    .FirstOrDefault(x => x.DecryptedGuid == targetRecordsID0)?.Record;

                                if (itemToRemove != null)
                                {
                                    tempModel_CWW_Records.ListModel_CWW_RTF_Records.Remove(itemToRemove);
                                    tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                        ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                }
                                else
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Null content, but not found records based on EncryptedGUID";
                                    tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                        ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                }
                            }
                            else
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += $"Received TEMP GUID";

                                targetRecordsID0 = UnicodeReaderMachine.ConvertByteArrayToGuid(
                                    tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_InserOrUpdateRecordsAndLogsx.TempNewGUID);


                                tempModel_CampMember_ServiceContext.ErrorMessage += $"HHSSSSS:::";

                                while (!hotCryptoService.CryptoServiceStatus)
                                {
                                    await Task.Delay(50);
                                }


                                Model_CampWorthwhileLogs_RTF_Records? itemToRemove = null;
                                if (tempModel_CWW_Records?.ListModel_CWW_RTF_Records == null)
                                {

                                }
                                else
                                {
                                    // Decrypt all existing record GUIDs in parallel
                                    var decryptTasks = tempModel_CWW_Records.ListModel_CWW_RTF_Records
                                        .Select(async r => new
                                        {
                                            Record = r,
                                            DecryptedGuid = UnicodeReaderMachine.ConvertByteArrayToGuid(
                                                await hotCryptoService.DecryptWithCommonAgency(r.RSAEncryptedUniqueIdentifier))
                                        }).ToList();




                                    var decryptedResults = await Task.WhenAll(decryptTasks);

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Decrypt Done:::";

                                    itemToRemove = decryptedResults
                                        .FirstOrDefault(x => x.DecryptedGuid == targetRecordsID0)?.Record;

                                }

                                if (itemToRemove != null)
                                {

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Found records";

                                    tempModel_CWW_Records.ListModel_CWW_RTF_Records.Remove(itemToRemove);
                                    tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                        ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                }
                                else
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Null content, or not found records based on TEMPID";
                                    tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                        ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                }
                            }
                        }
                        else
                        {


                            bool? isClassifiedAsTrialUserLimited10RecordsReached = null;

                            if (!tempModel_CampMember_ServiceContext.Model_AccountAgencyConsultResultsx.IsActiveCampMember)
                            {
                                int? recordsCount = tempModel_CWW_Records.ListModel_CWW_RTF_Records.Count;

                                tempModel_CampMember_ServiceContext.ErrorMessage += $"Records Count: {recordsCount}";

                                if (recordsCount >= 10)
                                {
                                    isClassifiedAsTrialUserLimited10RecordsReached = true;
                                }
                                else
                                {
                                    isClassifiedAsTrialUserLimited10RecordsReached = false;
                                }
                            }
                            else
                            {
                                isClassifiedAsTrialUserLimited10RecordsReached = false;
                            }

                            Guid targetRecordsID;
                            bool? IsRecordsExisted;
                            Model_CampWorthwhileLogs_RTF_Records matchedRecord = null;

                            tempModel_CampMember_ServiceContext.ErrorMessage += $"TTTT";


                            while (!hotCryptoService.CryptoServiceStatus)
                            {
                                await Task.Delay(50);
                            }

                            if (tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_InserOrUpdateRecordsAndLogsx.TempNewGUID != null)
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += $"WWWDDD";

                                targetRecordsID = UnicodeReaderMachine.ConvertByteArrayToGuid(tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_InserOrUpdateRecordsAndLogsx.TempNewGUID);
                            }
                            else
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += $"GJGJGJ";

                                targetRecordsID = UnicodeReaderMachine.ConvertByteArrayToGuid(await hotCryptoService.DecryptWithCommonAgency(tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_InserOrUpdateRecordsAndLogsx.EncryptedGUID));
                            }



                            tempModel_CampMember_ServiceContext.ErrorMessage += $"SSSS";



                            if (tempModel_CWW_Records?.ListModel_CWW_RTF_Records == null)
                            {
                                IsRecordsExisted = false;
                            }
                            else
                            {
                                // Create decryption tasks with records
                                var decryptTasks = tempModel_CWW_Records.ListModel_CWW_RTF_Records
                                    .Where(r => r.RSAEncryptedUniqueIdentifier != null)
                                    .Select(async r =>
                                    {
                                        Guid decryptedGuid = UnicodeReaderMachine.ConvertByteArrayToGuid(
                                            await hotCryptoService.DecryptWithCommonAgency(r.RSAEncryptedUniqueIdentifier));
                                        return new { Record = r, DecryptedGuid = decryptedGuid };
                                    }).ToList();

                                tempModel_CampMember_ServiceContext.ErrorMessage += $"QQQQ";

                                var decryptedResults = await Task.WhenAll(decryptTasks);

                                tempModel_CampMember_ServiceContext.ErrorMessage += $"AAAA";

                                // Check existence
                                IsRecordsExisted = decryptedResults.Any(x => x.DecryptedGuid == targetRecordsID);

                                tempModel_CampMember_ServiceContext.ErrorMessage += $"HHHHH";

                                matchedRecord = null;

                                if (IsRecordsExisted == true)
                                {
                                    matchedRecord = decryptedResults.FirstOrDefault(x => x.DecryptedGuid == targetRecordsID)?.Record;

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"JHYTT";
                                }
                            }





                            if (isClassifiedAsTrialUserLimited10RecordsReached == true)
                            {
                                if (IsRecordsExisted == true)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"sdadasd998";

                                    if (tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_InserOrUpdateRecordsAndLogsx.Content == null)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"FFFF";

                                        tempModel_CWW_Records.ListModel_CWW_RTF_Records.Remove(matchedRecord);

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"HJHJHH";

                                        await hotOracle_Object_Storage_Agency.CWWRecordsOverwrite(tempModel_CWW_Records);

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"SDSDSD";

                                        tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                    }
                                    else
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"OPPP";

                                        matchedRecord.RTFData = tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_InserOrUpdateRecordsAndLogsx.Content;
                                        matchedRecord.UpdateDate = DateTime.UtcNow;

                                        await hotOracle_Object_Storage_Agency.CWWRecordsOverwrite(tempModel_CWW_Records);

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"RRTR";

                                        tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                    }
                                }
                                else if (IsRecordsExisted == false)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Limit Reached";

                                    tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.RecordsReachedLimit = 1;
                                    tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                                    ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                }
                                else
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Error Messages LLLL";
                                }

                            }
                            else
                            {
                                if (IsRecordsExisted == true)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"SDSDSD";

                                    if (tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_InserOrUpdateRecordsAndLogsx.Content == null)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"56251";

                                        tempModel_CWW_Records.ListModel_CWW_RTF_Records.Remove(matchedRecord);

                                        await hotOracle_Object_Storage_Agency.CWWRecordsOverwrite(tempModel_CWW_Records);

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"9999";

                                        tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                    }
                                    else
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"BBBBB";

                                        matchedRecord.RTFData = tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_InserOrUpdateRecordsAndLogsx.Content;
                                        matchedRecord.UpdateDate = DateTime.UtcNow;

                                        await hotOracle_Object_Storage_Agency.CWWRecordsOverwrite(tempModel_CWW_Records);

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"><MKLL";

                                        tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                    }
                                }
                                else if (IsRecordsExisted == false)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"AAAA";

                                    Model_CampWorthwhileLogs_RTF_Records tempModel_CWW_RTF_Records = new Model_CampWorthwhileLogs_RTF_Records();

                                    tempModel_CWW_RTF_Records.RSAEncryptedUniqueIdentifier = await hotCryptoService.EncryptWithCommonAgency(tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_InserOrUpdateRecordsAndLogsx.TempNewGUID);

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"BBBB";
                                    tempModel_CWW_RTF_Records.RTFData = tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_InserOrUpdateRecordsAndLogsx.Content;
                                    tempModel_CWW_RTF_Records.CreateDate = DateTime.UtcNow;
                                    tempModel_CWW_RTF_Records.UpdateDate = DateTime.UtcNow;

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"CCCC";

                                    tempModel_CWW_Records.ListModel_CWW_RTF_Records.Add(tempModel_CWW_RTF_Records);

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"DDDD";

                                    await hotOracle_Object_Storage_Agency.CWWRecordsOverwrite(tempModel_CWW_Records);

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"EEEE";

                                    tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                }
                                else
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Error Messages LLLL";
                                }
                            }
                        }
                    }
                    else if (tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_DeleteRecordsAndLogsx != null)
                    {
                        CryptoService hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 4, null, null, null);

                        Model_CampWorthwhileLogs_Records? tempModel_CWW_Records = await hotOracle_Object_Storage_Agency.CWWRecordsDownload();


                        while (!hotCryptoService.CryptoServiceStatus)
                        {
                            await Task.Delay(50);
                        }

                        if (tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_DeleteRecordsAndLogsx?.GuidByte != null)
                        {
                            Guid targetRecordsID = UnicodeReaderMachine.ConvertByteArrayToGuid(tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_DeleteRecordsAndLogsx.GuidByte);

                            // Create decryption tasks with records
                            var decryptTasks = tempModel_CWW_Records.ListModel_CWW_RTF_Records
                                .Where(r => r.RSAEncryptedUniqueIdentifier != null)
                                .Select(async r =>
                                {
                                    Guid decryptedGuid = UnicodeReaderMachine.ConvertByteArrayToGuid(
                                        await hotCryptoService.DecryptWithCommonAgency(r.RSAEncryptedUniqueIdentifier));
                                    return new { Record = r, DecryptedGuid = decryptedGuid };
                                }).ToList();

                            var decryptedResults = await Task.WhenAll(decryptTasks);

                            // Check existence
                            bool IsRecordsExisted = decryptedResults.Any(x => x.DecryptedGuid == targetRecordsID);

                            Model_CampWorthwhileLogs_RTF_Records matchedRecord = null;

                            if (IsRecordsExisted)
                            {
                                matchedRecord = decryptedResults.FirstOrDefault(x => x.DecryptedGuid == targetRecordsID)?.Record;

                                tempModel_CWW_Records.ListModel_CWW_RTF_Records.Remove(matchedRecord);

                                await hotOracle_Object_Storage_Agency.CWWRecordsOverwrite(tempModel_CWW_Records);

                                tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                            }
                            else
                            {
                                tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }
                        else
                        {
                            Guid targetRecordsID = UnicodeReaderMachine.ConvertByteArrayToGuid(await hotCryptoService.DecryptWithCommonAgency(tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_DeleteRecordsAndLogsx.EncryptedGUID));

                            // Create decryption tasks with records
                            var decryptTasks = tempModel_CWW_Records.ListModel_CWW_RTF_Records
                                .Where(r => r.RSAEncryptedUniqueIdentifier != null)
                                .Select(async r =>
                                {
                                    Guid decryptedGuid = UnicodeReaderMachine.ConvertByteArrayToGuid(
                                        await hotCryptoService.DecryptWithCommonAgency(r.RSAEncryptedUniqueIdentifier));
                                    return new { Record = r, DecryptedGuid = decryptedGuid };
                                }).ToList();

                            var decryptedResults = await Task.WhenAll(decryptTasks);

                            // Check existence
                            bool IsRecordsExisted = decryptedResults.Any(x => x.DecryptedGuid == targetRecordsID);

                            Model_CampWorthwhileLogs_RTF_Records matchedRecord = null;

                            if (IsRecordsExisted)
                            {
                                matchedRecord = decryptedResults.FirstOrDefault(x => x.DecryptedGuid == targetRecordsID)?.Record;

                                tempModel_CWW_Records.ListModel_CWW_RTF_Records.Remove(matchedRecord);

                                await hotOracle_Object_Storage_Agency.CWWRecordsOverwrite(tempModel_CWW_Records);

                                tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                            }
                            else
                            {
                                tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }
                    }
                    else if (tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_FetchAllRecordsAndLogsx != null)
                    {
                        Model_CampWorthwhileLogs_Records? tempModel_CWW_Records = await hotOracle_Object_Storage_Agency.CWWRecordsDownload();

                        if (tempModel_CWW_Records == null)
                        {
                            tempModel_CWW_Records = new Model_CampWorthwhileLogs_Records();
                        }
                        else
                        {
                            tempConfiguration_CWWClientRequestResults.Main_CWW_DataModel_FromServerx.Model_CWW_Recordsx = tempModel_CWW_Records;
                        }

                        tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                        ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                    }
                    else if (tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_RequestRevokeServerSessionx != null)
                    {
                        //EntraIDAdminAgency hotEntraIDAdminAgency = new EntraIDAdminAgency(tempModel_CampMember_ServiceContext);

                        //try
                        //{
                        //    await hotEntraIDAdminAgency.RevokeUserSession();

                        //    tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                        //}
                        //catch (Exception ex)
                        //{
                        //    tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);

                        //    tempModel_CampMember_ServiceContext.ErrorMessage += $"Failed to authenticate point person admin: {ex.Message}";
                        //}
                    }
                    else if (tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_ReqSessionToBuyAGoodsx != null)
                    {
                        CampCommercialServer_Stripe_agency hotStripeAgency = new CampCommercialServer_Stripe_agency(tempModel_CampMember_ServiceContext);

                        int productToBePurchase = tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_ReqSessionToBuyAGoodsx.WhatToBuy;
                        int quantityToPurchase = tempMain_CWWRequest_FromClient.Main_CWW_DataModel_FromClientx.Model_ReqSessionToBuyAGoodsx.Quantity;

                        Model_CampStore_ReturnedSessionToBuyAGoods_ByteArray tempModel_ReturnedSessionToBuyAGoods_ByteArray = new Model_CampStore_ReturnedSessionToBuyAGoods_ByteArray();

                        //// Subscription to product 9.99 USD monthly
                        if (productToBePurchase == 1)
                        {
                            string sessionString = await hotStripeAgency.CreateRecurringCheckoutSession("price_1Pqu5HEgetNpsvbVClzUlNRQ", quantityToPurchase);
                            tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                        }
                        //// Subscription to product 299.00 USD monthly
                        else if (productToBePurchase == 2)
                        {
                            string sessionString = await hotStripeAgency.CreateRecurringCheckoutSession("price_1Pqu3pEgetNpsvbVS7lOUlFZ", quantityToPurchase);
                            tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                        }
                        // 4 is Individual key with 2048 bits 1 USD
                        else if (productToBePurchase == 4)
                        {
                            string sessionString = await hotStripeAgency.CreateHotPaymentCheckoutSession("price_1Q6GxaEgetNpsvbV8f53yoX1", quantityToPurchase);
                            tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                        }
                        // 5 is Individual key with 3072 bits 4 USD
                        else if (productToBePurchase == 5)
                        {
                            string sessionString = await hotStripeAgency.CreateHotPaymentCheckoutSession("price_1Q6GxoEgetNpsvbVFhDdcylW", quantityToPurchase);
                            tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                        }
                        // 6 is Individual key with 4096 bits 5 USD
                        else if (productToBePurchase == 6)
                        {
                            string sessionString = await hotStripeAgency.CreateHotPaymentCheckoutSession("price_1Q6GxxEgetNpsvbV9nIDAScw", quantityToPurchase);
                            tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                        }
                        // 7 is Monthly 1.99 USD
                        else if (productToBePurchase == 7)
                        {
                            string sessionString = await hotStripeAgency.CreateRecurringCheckoutSession("price_1R0n9pEgetNpsvbVUQPtm4Cd", quantityToPurchase);
                            tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                        }
                        // 8 is Monthly 59 USD
                        else if (productToBePurchase == 8)
                        {
                            string sessionString = await hotStripeAgency.CreateRecurringCheckoutSession("price_1R0nAnEgetNpsvbVEOBfGFnV", quantityToPurchase);
                            tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                        }
                        // Lifetime 599 USD
                        else if (productToBePurchase == 999)
                        {
                            CampCommercialServer_Stripe_agency hotStripeAgency999 = new CampCommercialServer_Stripe_agency(tempModel_CampMember_ServiceContext);

                            if (await hotStripeAgency999.CountProductSalesByPriceIdAsyncSuggestFor1UnitSales("price_1Q87BMEgetNpsvbVPwgdx0vo") > 10)
                            {
                                tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                            else
                            {
                                string sessionString = await hotStripeAgency.CreateHotPaymentCheckoutSession("price_1Q87BMEgetNpsvbVPwgdx0vo", 1);
                                tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                            }
                        }

                        tempConfiguration_CWWClientRequestResults.Main_CWW_DataModel_FromServerx.Model_ReturnedSessionToBuyAGoods_ByteArrayx = tempModel_ReturnedSessionToBuyAGoods_ByteArray;

                        tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult =
                            ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                    }
                    else
                    {
                        tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                    }
                }
                catch (Exception ex)
                {
                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Camp_Worthwhile_Logs_Service error: {ex.Message}";
                }






                MainSW.Stop();

                tempModel_CampMember_ServiceContext.ErrorMessage += $"Camp_Worthwhile_Logs_Service Elapse time: {MainSW.ElapsedMilliseconds} ms";

                tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages += tempModel_CampMember_ServiceContext.ErrorMessage;
                await hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency.AppendCampMemberServerLogAsync(tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages);

                byte[] protobufData;
                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, tempConfiguration_CWWClientRequestResults);
                    protobufData = stream.ToArray();
                }

                return protobufData;

            }
            catch (Exception ex)
            {
                tempModel_CampMember_ServiceContext.ErrorMessage += $"Camp_Worthwhile_Logs_Service RunService error: {ex.Message}";


                tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages += tempModel_CampMember_ServiceContext.ErrorMessage;
                await hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency.AppendCampMemberServerLogAsync(tempConfiguration_CWWClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages);

                byte[] protobufData;
                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, tempConfiguration_CWWClientRequestResults);
                    protobufData = stream.ToArray();
                }

                return protobufData;
            }














        }





        }
}
