using CroftTeamsWinUITemplate.Models;
using CroftTeamsWinUITemplate.Services.HotAgency;
using CroftTeamsWinUITemplate.Services.Machines;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Utilities.Collections;
using ProtoBuf;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net.Http.Headers;

namespace campmember_commercial_webapp_linuximg.Services
{
    public class Camp_Dating_Service
    {
        Model_CampMember_ServiceContext tempModel_CampMember_ServiceContext;
        Main_CampDating_Request_FromClient tempMain_CampDating_Request_FromClient;
        Configuration_CampDating_ClientRequestResults tempConfiguration_CampDating_ClientRequestResults;

        CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency hotBlob_Agency_CampMemberBlob;
        CampCommercialServer_BucketInMachine hotCampCommercialServerBucketMachine;

        public Camp_Dating_Service(Model_CampMember_ServiceContext context, Main_CampDating_Request_FromClient data)
        {
            tempModel_CampMember_ServiceContext = context;

            tempMain_CampDating_Request_FromClient = data;

            tempConfiguration_CampDating_ClientRequestResults = new Configuration_CampDating_ClientRequestResults
            {
                Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult
                {

                },
                Main_CampDating_DataModel_FromServerx = new Main_CampDating_DataModel_FromServer
                {

                },

                JobID = tempMain_CampDating_Request_FromClient.JobID
            };



            hotBlob_Agency_CampMemberBlob = new CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency(context);
            hotCampCommercialServerBucketMachine = new CampCommercialServer_BucketInMachine(context);





        }

        public async Task<byte[]> RunService()
        {

            try
            {
                var MainSW = Stopwatch.StartNew();

                // BLOB NOW!
                if (tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_FetchOwnerProfilex != null)
                {
                    try
                    {
                        tempModel_CampMember_ServiceContext.ErrorMessage += $"Fetch Owner profile";

                        Model_CampDating_Public_Profiles_Client? tempModel_CampDating_Public_Profiles_Client = await hotCampCommercialServerBucketMachine.CDTProfileDownload(null);

                        if (tempModel_CampDating_Public_Profiles_Client == null)
                        {
                            tempConfiguration_CampDating_ClientRequestResults.Main_CampDating_DataModel_FromServerx.Model_CampDating_Public_Profiles_Clientx = new Model_CampDating_Public_Profiles_Client()
                            {
                                Latitude_Longtitude_Collection = new Model_CampMember_Latitude_Longtitude()
                            };

                            tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                        }
                        else
                        {
                            tempConfiguration_CampDating_ClientRequestResults.Main_CampDating_DataModel_FromServerx.Model_CampDating_Public_Profiles_Clientx = tempModel_CampDating_Public_Profiles_Client;

                            tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                        }
                    }
                    catch (Exception ex)
                    {
                        tempModel_CampMember_ServiceContext.ErrorMessage += $"Camp_Dating_Service Model_CampDating_FetchOwnerProfilex error : {ex.Message}";

                        tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                    }
                }

                else if (tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_OpenOthersProfilex != null)
                {
                    try
                    {
                        CryptoService hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 3, null, null, null);

                        string TargetHEXUserIdentifierSHA = ByteArrayAndConversionMachine.ConvertBytesToHex(await hotCryptoService.DecryptWithCommonAgency(tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_OpenOthersProfilex.Encrypted_Target_UserIdentifier_SHA));

                        Model_CampDating_Public_Profiles_Client? tempModel_CampDating_Public_Profiles_Client = await hotCampCommercialServerBucketMachine.CDTProfileDownload(TargetHEXUserIdentifierSHA);

                        bool IsBeingBlocked;

                        if (tempModel_CampDating_Public_Profiles_Client.ListOfBlockedUser == null)
                        {
                            IsBeingBlocked = false;
                        }
                        else
                        {
                            IsBeingBlocked = tempModel_CampDating_Public_Profiles_Client.ListOfBlockedUser.Contains(tempModel_CampMember_ServiceContext.user_IdentifierSHAHEX);
                        }

                        if (!IsBeingBlocked)
                        {
                            bool isPrivateAllowed;

                            if (tempModel_CampDating_Public_Profiles_Client.AllowedUserOnPrivatePicture == null)
                            {
                                isPrivateAllowed = false;
                            }
                            else
                            {
                                isPrivateAllowed = tempModel_CampDating_Public_Profiles_Client.AllowedUserOnPrivatePicture.Contains(tempModel_CampMember_ServiceContext.user_IdentifierSHAHEX);
                            }

                            if (isPrivateAllowed)
                            {

                            }
                            else
                            {
                                if (tempModel_CampDating_Public_Profiles_Client.ListModel_CampDating_Dynamic_Picturex != null)
                                {
                                    tempModel_CampDating_Public_Profiles_Client.ListModel_CampDating_Dynamic_Picturex.RemoveAll(p => p.SpecialLocator == 2);
                                }
                                else
                                {

                                }
                            }


                            // Clear personal configuration out.

                            tempModel_CampDating_Public_Profiles_Client.Latitude_Longtitude_Collection = null;

                            tempModel_CampDating_Public_Profiles_Client.Stealth = null;

                            tempModel_CampDating_Public_Profiles_Client.ListOfBlockedUser = null;

                            tempModel_CampDating_Public_Profiles_Client.AllowedUserOnPrivatePicture = null;


                            tempModel_CampDating_Public_Profiles_Client.EncryptedUserIdentifierSHA = tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_OpenOthersProfilex.Encrypted_Target_UserIdentifier_SHA;









                            List<Model_CampDating_SpecificChatHistory> tempListModel_CampDating_SpecificChatHistory = new List<Model_CampDating_SpecificChatHistory>();

                            List<string>? ListChatRoomHEX = await hotBlob_Agency_CampMemberBlob.CDTGetChatIDListInUserChatCollection();

                            int ChatCollectionCount = ListChatRoomHEX.Count;

                            tempModel_CampMember_ServiceContext.ErrorMessage += $"ChatCollectionCount {ChatCollectionCount}";





                            if (ListChatRoomHEX != null)
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += $"DDDDDDDDDDD";

                                using var cts = new CancellationTokenSource();
                                var token = cts.Token;
                                List<Model_CampDating_SpecificChatHistory?> matchedChats = new();

                                var tasks = ListChatRoomHEX.Select<string, Task>(async chatId =>
                                {
                                    try
                                    {
                                        if (token.IsCancellationRequested) return;

                                        var chat = await hotCampCommercialServerBucketMachine.CDTSpecificChatHistoryDownload(chatId);
                                        if (chat != null)
                                        {
                                            chat.TempChatID = ByteArrayAndConversionMachine.ConvertHexToOriginal(chatId);

                                            if (chat.RoomType == 0 &&
                                                GetOtherParticipants(chat.Pariticipant).Contains(TargetHEXUserIdentifierSHA))
                                            {
                                                chat.TempChatID = await hotCryptoService.EncryptWithCommonAgency(ByteArrayAndConversionMachine.ConvertHexToOriginal(chatId));

                                                // Use new function here
                                                var participants = GetAllParticipants(chat.Pariticipant);

                                                var speakerImages = new Dictionary<int, byte[]>();

                                                // Collect unique senders once
                                                var uniqueSenders = chat.MessageHistory
                                                    .Where(m => !string.IsNullOrEmpty(m.HEXSenderId))
                                                    .Select(m => m.HEXSenderId)
                                                    .Distinct()
                                                    .ToList();

                                                var profileCache = new ConcurrentDictionary<string, Model_CampDating_Public_Profiles_Client>();

                                                var downloadTasks = uniqueSenders.Select(async sender =>
                                                {
                                                    var profile = await hotCampCommercialServerBucketMachine.CDTProfileDownload(sender);
                                                    profileCache[sender] = profile;
                                                });

                                                await Task.WhenAll(downloadTasks);

                                                foreach (var sender in uniqueSenders)
                                                {
                                                    int idx = GetParticipantIndex1Based(chat.Pariticipant, sender);
                                                    if (idx != -1 && profileCache.TryGetValue(sender, out var profile))
                                                    {
                                                        var pictureObj = profile?.ListModel_CampDating_Dynamic_Picturex?.FirstOrDefault(p => p.SpecialLocator == 0);
                                                        if (pictureObj?.Picture != null && !speakerImages.ContainsKey(idx))
                                                        {
                                                            speakerImages[idx] = pictureObj.Picture;
                                                        }
                                                    }
                                                }

                                                chat.SpeakerImages = speakerImages;

                                                foreach (var msg in chat.MessageHistory)
                                                {
                                                    if (string.IsNullOrEmpty(msg.HEXSenderId)) continue;

                                                    if (profileCache.TryGetValue(msg.HEXSenderId, out var profile))
                                                    {
                                                        msg.HotSpeakerName = profile?.DisplayName != null
                                                            ? UnicodeReaderMachine.ByteArrayToUnicodeAsync(profile.DisplayName)
                                                            : "(unknown)";

                                                        int idx = GetParticipantIndex1Based(chat.Pariticipant, msg.HEXSenderId);
                                                        msg.HEXSenderId = idx != -1 ? idx.ToString() : msg.HEXSenderId;
                                                    }
                                                }

                                                lock (matchedChats)
                                                {
                                                    matchedChats.Add(chat);
                                                }
                                            }
                                        }
                                    }
                                    catch
                                    {
                                        // ignore or log
                                    }
                                }).ToList();

                                await Task.WhenAll(tasks);

                                if (matchedChats.Count == 1)
                                {
                                    tempConfiguration_CampDating_ClientRequestResults.Main_CampDating_DataModel_FromServerx.Model_CampDating_SpecificChatHistoryx = matchedChats[0];
                                }
                                else if (matchedChats.Count == 0)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"No matching 1-on-1 chat found.";
                                }
                                else
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"Multiple matching 1-on-1 chats found.";
                                }
                            }

                            tempConfiguration_CampDating_ClientRequestResults.Main_CampDating_DataModel_FromServerx.Model_CampDating_Public_Profiles_Clientx = tempModel_CampDating_Public_Profiles_Client;



                            tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                        }
                        else
                        {
                            tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                        }
                    }
                    catch (Exception ex)
                    {
                        tempModel_CampMember_ServiceContext.ErrorMessage += $"Camp_Dating_Service Model_CampDating_OpenOthersProfilex error : {ex.Message}";
                    }
                }

                else if (tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_FetchingCDTFeedsx != null)
                {
                    try
                    {
                        tempModel_CampMember_ServiceContext.ErrorMessage += $"Fetch Feeds";

                        CryptoService hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 3, null, null, null);

                        tempModel_CampMember_ServiceContext.ErrorMessage += $"AAAA";

                        bool? IsUserDefinedFixLocation = await hotBlob_Agency_CampMemberBlob.IsUserLatitudeDefinedAsync();


                        tempModel_CampMember_ServiceContext.ErrorMessage += $"BBBB";

                        if (tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_FetchingCDTFeedsx.Latitude_Longitude != null)
                        {

                            tempModel_CampMember_ServiceContext.ErrorMessage += $"CCCC";

                            var lat = tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_FetchingCDTFeedsx.Latitude_Longitude?.lat;
                            var lng = tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_FetchingCDTFeedsx.Latitude_Longitude?.lng;


                            tempModel_CampMember_ServiceContext.ErrorMessage += $"DDDD";

                            double? posX = null;
                            double? posY = null;

                            if (lat.HasValue && lng.HasValue)
                            {
                                (posX, posY) = LatLonToMercator(lat.Value, lng.Value);
                            }


                            tempModel_CampMember_ServiceContext.ErrorMessage += $"EEEE";

                            List<Model_CampDating_HotFeedProfile_Server> ListModel_CDT_HotFeedProfile_Server = await hotBlob_Agency_CampMemberBlob.GetNearbyHotFeedProfilesAsync(tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_FetchingCDTFeedsx.Radius, posX);

                            List<Model_CampDating_HotProfile_Server> ListModel_HotProfile_Server = new();


                            tempModel_CampMember_ServiceContext.ErrorMessage += $"FFFF";

                            var tasks = ListModel_CDT_HotFeedProfile_Server.Select(async user =>
                            {
                                try
                                {

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"GGGG";

                                    Model_CampDating_Public_Profiles_Client tempProfile = await hotCampCommercialServerBucketMachine.CDTProfileDownload(user.HEXUserIdentifierSHA);


                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"HHHH";

                                    if (ByteArrayAndConversionMachine.ConvertByteArrayToBool(tempProfile.Stealth))
                                        return null; // skip stealth profiles

                                    Model_CampDating_HotProfile_Server tempModel = new Model_CampDating_HotProfile_Server();

                                    while (!hotCryptoService.CryptoServiceStatus)
                                    {
                                        await Task.Delay(50);
                                    }


                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"IIII";

                                    tempModel.EncryptedUserIdentifier_SHA = await hotCryptoService.EncryptWithCommonAgency(
                                        ByteArrayAndConversionMachine.ConvertHexToOriginal(user.HEXUserIdentifierSHA));

                                    tempModel.Distance = user.Distance;
                                    tempModel.DisplayName = tempProfile?.DisplayName ?? new byte[] { 0 };

                                    Model_CampDating_Dynamic_Picture? pic = tempProfile?.ListModel_CampDating_Dynamic_Picturex?
                                        .FirstOrDefault(p => p.SpecialLocator == 0);


                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"JJJJ";

                                    if (pic != null)
                                        tempModel.Picture = pic.Picture;

                                    return tempModel;
                                }
                                catch (Exception ex)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage +=
                                        $"Camp_Dating_Service Model_CampDating_FetchingCDTFeedsx error : {ex.Message}";
                                    return null;
                                }
                            });

                            var results = await Task.WhenAll(tasks);
                            ListModel_HotProfile_Server = results.Where(r => r != null).ToList();


                            tempModel_CampMember_ServiceContext.ErrorMessage += $"KKKK";

                            tempConfiguration_CampDating_ClientRequestResults.Main_CampDating_DataModel_FromServerx.ListModel_HotProfile_Serverx =
                                ListModel_HotProfile_Server;

                            tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);

                        }
                        else
                        {

                            if (IsUserDefinedFixLocation == false)
                            {

                                tempModel_CampMember_ServiceContext.ErrorMessage += $"No Location defined";

                                tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = new byte[] { 0 };
                            }
                            else
                            {

                                tempModel_CampMember_ServiceContext.ErrorMessage += $"XXdfdsf";

                                List<Model_CampDating_HotFeedProfile_Server> ListModel_CDT_HotFeedProfile_Server = await hotBlob_Agency_CampMemberBlob.GetNearbyHotFeedProfilesAsync(tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_FetchingCDTFeedsx.Radius, null);

                                List<Model_CampDating_HotProfile_Server> ListModel_HotProfile_Server = new();


                                tempModel_CampMember_ServiceContext.ErrorMessage += $"AAAA";

                                var tasks = ListModel_CDT_HotFeedProfile_Server.Select(async user =>
                                {
                                    try
                                    {
                                        Model_CampDating_Public_Profiles_Client tempProfile = await hotCampCommercialServerBucketMachine.CDTProfileDownload(user.HEXUserIdentifierSHA);


                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"BBBB";

                                        if (ByteArrayAndConversionMachine.ConvertByteArrayToBool(tempProfile.Stealth))
                                            return null; // skip stealth profiles

                                        Model_CampDating_HotProfile_Server tempModel = new Model_CampDating_HotProfile_Server();

                                        while (!hotCryptoService.CryptoServiceStatus)
                                        {
                                            await Task.Delay(50);
                                        }


                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"CCCC";

                                        tempModel.EncryptedUserIdentifier_SHA = await hotCryptoService.EncryptWithCommonAgency(
                                            ByteArrayAndConversionMachine.ConvertHexToOriginal(user.HEXUserIdentifierSHA));


                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"DDDD";

                                        tempModel.Distance = user.Distance;
                                        tempModel.DisplayName = tempProfile?.DisplayName ?? new byte[] { 0 };

                                        Model_CampDating_Dynamic_Picture? pic = tempProfile?.ListModel_CampDating_Dynamic_Picturex?
                                            .FirstOrDefault(p => p.SpecialLocator == 0);


                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"EEEE";

                                        if (pic != null)
                                            tempModel.Picture = pic.Picture;

                                        return tempModel;
                                    }
                                    catch (Exception ex)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage +=
                                            $"Camp_Dating_Service Model_CampDating_FetchingCDTFeedsx error : {ex.Message}";
                                        return null;
                                    }
                                });


                                tempModel_CampMember_ServiceContext.ErrorMessage += $"FFFF";

                                var results = await Task.WhenAll(tasks);
                                ListModel_HotProfile_Server = results.Where(r => r != null).ToList();


                                tempModel_CampMember_ServiceContext.ErrorMessage += $"GGGG";

                                tempConfiguration_CampDating_ClientRequestResults.Main_CampDating_DataModel_FromServerx.ListModel_HotProfile_Serverx =
                                    ListModel_HotProfile_Server;

                                tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                            }
                        }




                    }
                    catch (Exception ex)
                    {
                        tempModel_CampMember_ServiceContext.ErrorMessage += $"Camp_Dating_Service Model_CampDating_FetchingCDTFeedsx error : {ex.Message}";

                        tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                    }
                }

                else if (tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_UpdateOwnerProfilex != null)
                {
                    try
                    {
                        await hotCampCommercialServerBucketMachine.CDTProfileOverwrite(tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_UpdateOwnerProfilex.tempModel_CampDating_Public_Profiles_Client);

                        if (tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_UpdateOwnerProfilex.tempModel_CampDating_Public_Profiles_Client.Latitude_Longtitude_Collection?.lat == null)
                        {
                            await hotBlob_Agency_CampMemberBlob.CDTUpdateUserLocationToEmpty();
                        }
                        else
                        {
                            await hotBlob_Agency_CampMemberBlob.CDTUpdateUserLocation(tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_UpdateOwnerProfilex.tempModel_CampDating_Public_Profiles_Client.Latitude_Longtitude_Collection);
                        }

                        tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                    }
                    catch (Exception ex)
                    {
                        tempModel_CampMember_ServiceContext.ErrorMessage += $"Camp_Dating_Service Model_CampDating_UpdateOwnerProfilex error : {ex.Message}";

                        tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                    }
                }

                else if (tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_FetchPartyListx != null)
                {
                    try
                    {
                        CryptoService hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 3, null, null, null);

                        List<string> ListOfChat = await hotBlob_Agency_CampMemberBlob.CDTGetChatIDListInUserChatCollection();

                        var tasks0 = ListOfChat.Select(async chatId =>
                        {
                            var history = await hotCampCommercialServerBucketMachine.CDTSpecificChatHistoryDownload(chatId);
                            if (history != null)
                            {
                                history.TempChatID = await hotCryptoService.EncryptWithCommonAgency(ByteArrayAndConversionMachine.ConvertHexToOriginal(chatId));
                            }
                            return history;
                        }).ToList();

                        Model_CampDating_SpecificChatHistory[] results = await Task.WhenAll(tasks0);

                        List<Model_CampDating_SpecificChatHistory> ListModel_CampDating_SpecificChatHistory =
                            results.Where(r => r != null).ToList();


                        var profileCache = new Dictionary<string, Model_CampDating_Public_Profiles_Client>();

                        async Task<Model_CampDating_Public_Profiles_Client?> GetProfileAsync(string userId)
                        {
                            if (profileCache.TryGetValue(userId, out var cached))
                                return cached;

                            var profile = await hotCampCommercialServerBucketMachine.CDTProfileDownload(userId);
                            profileCache[userId] = profile;
                            return profile;
                        }

                        var tasks1 = ListModel_CampDating_SpecificChatHistory.Select(async history =>
                        {
                            byte[] image = new byte[0];
                            var others = GetOtherParticipants(history.Pariticipant);

                            if (others.Count > 0)
                            {
                                var profile = await GetProfileAsync(others[0]);
                                image = profile?.ListModel_CampDating_Dynamic_Picturex
                                    ?.FirstOrDefault(p => p.SpecialLocator == 0)?.Picture ?? new byte[0];
                            }

                            var latestMessage = history.MessageHistory?
                                .OrderByDescending(m => m.Timestamp)
                                .FirstOrDefault();

                            byte[] speakerDisplayName = new byte[0];
                            if (latestMessage != null)
                            {
                                var senderProfile = await GetProfileAsync(latestMessage.HEXSenderId);
                                speakerDisplayName = senderProfile?.DisplayName ?? new byte[0];
                            }

                            return new Model_CampDating_ChatPartyCollection
                            {
                                ChatID = history.TempChatID,
                                Alias = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(history.RoomAliasName),
                                Image = image,
                                LatestMessage = latestMessage != null
                                    ? new Model_CampDating_LatestMessage
                                    {
                                        Speaker = speakerDisplayName,
                                        SpeakDateTime = latestMessage.Timestamp,
                                        Message = latestMessage.Message
                                    }
                                    : new Model_CampDating_LatestMessage
                                    {
                                        Speaker = new byte[0],
                                        SpeakDateTime = DateTime.MinValue,
                                        Message = new byte[0]
                                    },
                                UnreadIndicator = latestMessage?.ReadIndicator ?? new byte[0]
                            };
                        });

                        List<Model_CampDating_ChatPartyCollection> ListModel_CampDating_ChatPartyCollection = (await Task.WhenAll(tasks1)).ToList();

                        tempConfiguration_CampDating_ClientRequestResults.Main_CampDating_DataModel_FromServerx.ListModel_CampDating_ChatPartyCollectionx = ListModel_CampDating_ChatPartyCollection;

                        tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                    }
                    catch (Exception ex)
                    {
                        tempModel_CampMember_ServiceContext.ErrorMessage += $"Camp_Dating_Service Model_CDT_FetchPartyListx error : {ex.Message}";

                        tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                    }
                }

                else if (tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_SendChatMessagex != null)
                {
                    try
                    {
                        CryptoService hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 3, null, null, null);

                        if (tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_SendChatMessagex.EncryptedChatID == null)
                        {
                            tempModel_CampMember_ServiceContext.ErrorMessage += $"1.EncryptedChatID == null";

                            if (tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_SendChatMessagex.EncryptedParticipantIdentifierSHA != null)
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += $"AAAAA";

                                while (!hotCryptoService.CryptoServiceStatus)
                                {
                                    await Task.Delay(50);
                                }

                                tempModel_CampMember_ServiceContext.ErrorMessage += $"BBBB";

                                string participantHEX = ByteArrayAndConversionMachine.ConvertBytesToHex(await hotCryptoService.DecryptWithCommonAgency(tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_SendChatMessagex.EncryptedParticipantIdentifierSHA));

                                tempModel_CampMember_ServiceContext.ErrorMessage += $"CCCC";

                                bool? isParticipantExisted = await hotCampCommercialServerBucketMachine.CDTProfileCheckExistance(participantHEX);

                                tempModel_CampMember_ServiceContext.ErrorMessage += $"DDDD";

                                if (isParticipantExisted == true)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"EEEE";

                                    string ChatPartifipant = AddParticipant(tempModel_CampMember_ServiceContext.user_IdentifierSHAHEX, participantHEX);

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"FFFF";

                                    Model_CampDating_SpecificChatHistory tempModel_CampDating_SpecificChatHistory = new Model_CampDating_SpecificChatHistory()
                                    {
                                        RoomAliasName = tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_SendChatMessagex.RoomAliasName,

                                        RoomOwner = tempModel_CampMember_ServiceContext.user_IdentifierSHAHEX,

                                        RoomType = 0,

                                        MessageHistory = new List<Model_CampDating_ChatMessage>(),

                                        Pariticipant = AddParticipant(tempModel_CampMember_ServiceContext.user_IdentifierSHAHEX, participantHEX),

                                        CreatedAt = DateTime.Now,

                                        UpdatedAt = DateTime.Now,
                                    };

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"GGGG";

                                    Model_CampDating_ChatMessage tempChatMessage = new Model_CampDating_ChatMessage()
                                    {
                                        HEXSenderId = tempModel_CampMember_ServiceContext.user_IdentifierSHAHEX,

                                        MessageType = 0,

                                        Message = tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_SendChatMessagex.Message,

                                        Timestamp = DateTime.Now,

                                        ReadIndicator = new byte[] { 0 },
                                    };

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"HHHH";

                                    tempModel_CampDating_SpecificChatHistory.MessageHistory.Add(tempChatMessage);

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"IIII";

                                    byte[] ChatRoomHash = ByteArrayAndConversionMachine.DoComputeByteArrayToSHA256Hash(UnicodeReaderMachine.ConvertUnicodeStringToByteArray(tempModel_CampDating_SpecificChatHistory.Pariticipant));

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"JJJJ";

                                    string HEXChatRoomHash = ByteArrayAndConversionMachine.ConvertBytesToHex(ChatRoomHash);

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"KKKK";

                                    await hotCampCommercialServerBucketMachine.CDTOverwriteChatRoom(HEXChatRoomHash, tempModel_CampDating_SpecificChatHistory);

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"LLLL";

                                    bool IsChatAlreadyBeenRegistered = await hotBlob_Agency_CampMemberBlob.CDTCheckChatIDExists(tempModel_CampMember_ServiceContext.user_IdentifierSHAHEX, HEXChatRoomHash);

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"MMMM";

                                    if (IsChatAlreadyBeenRegistered)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"NNNN";

                                        Model_CampDating_New_ChatID tempModel_New_ChatID = new Model_CampDating_New_ChatID()
                                        {
                                            EncryptedChatID = await hotCryptoService.EncryptWithCommonAgency(ByteArrayAndConversionMachine.ConvertHexToOriginal(HEXChatRoomHash))
                                        };

                                        tempConfiguration_CampDating_ClientRequestResults.Main_CampDating_DataModel_FromServerx.Model_New_ChatIDx = tempModel_New_ChatID;

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"OOOO";
                                    }
                                    else
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"PPPP";

                                        await hotBlob_Agency_CampMemberBlob.CDTRegisterChatID(tempModel_CampMember_ServiceContext.user_IdentifierSHAHEX, HEXChatRoomHash);

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"QQQQ";

                                        await hotBlob_Agency_CampMemberBlob.CDTRegisterChatID(participantHEX, HEXChatRoomHash);

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"RRRR";

                                        Model_CampDating_New_ChatID tempModel_New_ChatID = new Model_CampDating_New_ChatID()
                                        {
                                            EncryptedChatID = await hotCryptoService.EncryptWithCommonAgency(ByteArrayAndConversionMachine.ConvertHexToOriginal(HEXChatRoomHash))
                                        };

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"SSSS";

                                        tempConfiguration_CampDating_ClientRequestResults.Main_CampDating_DataModel_FromServerx.Model_New_ChatIDx = tempModel_New_ChatID;
                                    }

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"TTTT";

                                    string? ParticipantConnectionID = await hotBlob_Agency_CampMemberBlob.GetConnectionIdOnLiveUserTableByUserHex(ByteArrayAndConversionMachine.ConvertBytesToHex(await hotCryptoService.DecryptWithCommonAgency(tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_SendChatMessagex.EncryptedParticipantIdentifierSHA)));

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"WWWW";

                                    // If user online or not
                                    if (string.IsNullOrEmpty(ParticipantConnectionID))
                                    {

                                    }
                                    else
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"XXXX";

                                        CampCommercialServer_Crypto_agency hotCampCryptoAgency = new CampCommercialServer_Crypto_agency(tempModel_CampMember_ServiceContext);

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"YYYY";

                                        Model_CampDating_OnlineUserMessage tempModel_CampDating_OnlineUserMessage = new Model_CampDating_OnlineUserMessage()
                                        {
                                            EncryptedCallerSHA = await hotCampCryptoAgency.EncryptwithAES(tempModel_CampMember_ServiceContext.user_IdentifierSHA256),

                                            EncryptedChatIDSHA = await hotCampCryptoAgency.EncryptwithAES(ByteArrayAndConversionMachine.ConvertHexToOriginal(HEXChatRoomHash)),

                                            Message = tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_SendChatMessagex.Message,
                                        };

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"ZZZZZ";

                                        tempModel_CampDating_OnlineUserMessage.ErrorMessage += tempModel_CampMember_ServiceContext.ErrorMessage;

                                        await Program.CampConnectServiceInstance.CampDating_Send_CDT_MessageToSpecificConnection(ParticipantConnectionID, tempModel_CampDating_OnlineUserMessage);
                                    }



                                    tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                }
                                else
                                {
                                    tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                }
                            }
                            else
                            {
                                tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                            }
                        }
                        else if (tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_SendChatMessagex.EncryptedChatID != null)
                        {
                            bool ChatWaitingForUpdate = true;

                            while (ChatWaitingForUpdate)
                            {
                                tempModel_CampMember_ServiceContext.ErrorMessage += $"AAAA";

                                string HEXChatID = ByteArrayAndConversionMachine.ConvertBytesToHex(await hotCryptoService.DecryptWithCommonAgency(tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_SendChatMessagex.EncryptedChatID));

                                tempModel_CampMember_ServiceContext.ErrorMessage += $"BBBB";

                                Model_CampDating_SpecificChatHistory? tempModel_CampDating_SpecificChatHistory0 = await hotCampCommercialServerBucketMachine.CDTSpecificChatHistoryDownload(HEXChatID);

                                tempModel_CampMember_ServiceContext.ErrorMessage += $"CCCC";

                                if (tempModel_CampDating_SpecificChatHistory0 != null)
                                {
                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"DDDD";

                                    bool IsCallerInTheList = IsParticipantInList(tempModel_CampDating_SpecificChatHistory0.Pariticipant, tempModel_CampMember_ServiceContext.user_IdentifierSHAHEX);

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"EEEE";

                                    if (IsCallerInTheList)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"FFFF";

                                        Model_CampDating_ChatMessage tempChatMessage = new Model_CampDating_ChatMessage()
                                        {
                                            HEXSenderId = tempModel_CampMember_ServiceContext.user_IdentifierSHAHEX,

                                            MessageType = 0,

                                            Message = tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_SendChatMessagex.Message,

                                            Timestamp = DateTime.Now,

                                            ReadIndicator = new byte[] { 0 },
                                        };

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"GGGG";

                                        tempModel_CampDating_SpecificChatHistory0.MessageHistory.Add(tempChatMessage);

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"HHHH";

                                        tempModel_CampDating_SpecificChatHistory0.MessageHistory = tempModel_CampDating_SpecificChatHistory0.MessageHistory.OrderBy(m => m.Timestamp).ToList();

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"IIII";

                                        tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                    }
                                    else
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"JJJJ";

                                        ChatWaitingForUpdate = false;

                                        tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                    }

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"KKKK";

                                    Model_CampDating_SpecificChatHistory? tempModel_CampDating_SpecificChatHistory1 = await hotCampCommercialServerBucketMachine.CDTSpecificChatHistoryDownload(ByteArrayAndConversionMachine.ConvertBytesToHex(await hotCryptoService.DecryptWithCommonAgency(tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_SendChatMessagex.EncryptedChatID)));

                                    tempModel_CampMember_ServiceContext.ErrorMessage += $"LLLL";

                                    if (tempModel_CampDating_SpecificChatHistory0.UpdatedAt == tempModel_CampDating_SpecificChatHistory1.UpdatedAt)
                                    {
                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"MMMM";

                                        await hotCampCommercialServerBucketMachine.CDTOverwriteChatRoom(HEXChatID, tempModel_CampDating_SpecificChatHistory0);

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"NNNN";

                                        string? ParticipantConnectionID = await hotBlob_Agency_CampMemberBlob.GetConnectionIdOnLiveUserTableByUserHex(ByteArrayAndConversionMachine.ConvertBytesToHex(await hotCryptoService.DecryptWithCommonAgency(tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_SendChatMessagex.EncryptedParticipantIdentifierSHA)));

                                        tempModel_CampMember_ServiceContext.ErrorMessage += $"OOOO";

                                        if (string.IsNullOrEmpty(ParticipantConnectionID))
                                        {

                                        }
                                        else
                                        {
                                            tempModel_CampMember_ServiceContext.ErrorMessage += $"PPPP";

                                            CampCommercialServer_Crypto_agency hotCampCryptoAgency = new CampCommercialServer_Crypto_agency(tempModel_CampMember_ServiceContext);

                                            tempModel_CampMember_ServiceContext.ErrorMessage += $"QQQQ";

                                            Model_CampDating_OnlineUserMessage tempModel_CampDating_OnlineUserMessage = new Model_CampDating_OnlineUserMessage()
                                            {
                                                EncryptedCallerSHA = await hotCampCryptoAgency.EncryptwithAES(tempModel_CampMember_ServiceContext.user_IdentifierSHA256),

                                                EncryptedChatIDSHA = await hotCampCryptoAgency.EncryptwithAES(ByteArrayAndConversionMachine.ConvertHexToOriginal(HEXChatID)),

                                                Message = tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_SendChatMessagex.Message,
                                            };

                                            tempModel_CampMember_ServiceContext.ErrorMessage += $"WWWW";

                                            tempModel_CampDating_OnlineUserMessage.ErrorMessage += tempModel_CampMember_ServiceContext.ErrorMessage;

                                            await Program.CampConnectServiceInstance.CampDating_Send_CDT_MessageToSpecificConnection(ParticipantConnectionID, tempModel_CampDating_OnlineUserMessage);

                                            tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                                        }

                                        ChatWaitingForUpdate = false;
                                    }
                                    else
                                    {

                                    }
                                }
                                else
                                {
                                    tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                                }
                            }
                        }
                        else
                        {
                            tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                        }

                    }
                    catch (Exception ex)
                    {
                        tempModel_CampMember_ServiceContext.ErrorMessage += $"Camp_Dating_Service Model_SendChatMessagex error : {ex.Message}";
                    }
                }

                else if (tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_CheckMessageTargetx != null)
                {
                    try
                    {
                        CampCommercialServer_Crypto_agency hotCampCryptoAgency = new CampCommercialServer_Crypto_agency(tempModel_CampMember_ServiceContext);
                        CryptoService hotCryptoService = new CryptoService(tempModel_CampMember_ServiceContext, 3, null, null, null);

                        tempModel_CampMember_ServiceContext.ErrorMessage += $"AAAA";

                        byte[] decryptedChatIDTarget = await hotCampCryptoAgency.DecryptwithAES(
                            tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_CheckMessageTargetx.EncryptedChatTargetSHA);

                        tempModel_CampMember_ServiceContext.ErrorMessage += $"BBBB";

                        List<byte[]> chatIDList = tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_CheckMessageTargetx.ListHexChatID;

                        tempModel_CampMember_ServiceContext.ErrorMessage += $"CCCC";

                        while (!hotCryptoService.CryptoServiceStatus)
                        {
                            await Task.Delay(50);
                        }

                        tempModel_CampMember_ServiceContext.ErrorMessage += $"DDDD";

                        List<byte[]> matchedEncryptedChatIDs = new();

                        var tasks = chatIDList.Select(async id =>
                        {
                            var decryptedChatID = await hotCryptoService.DecryptWithCommonAgency(id);

                            if (decryptedChatID.SequenceEqual(decryptedChatIDTarget))
                            {
                                lock (matchedEncryptedChatIDs)
                                {
                                    matchedEncryptedChatIDs.Add(id);
                                }
                            }
                        }).ToArray();

                        tempModel_CampMember_ServiceContext.ErrorMessage += $"EEEE";

                        try
                        {
                            await Task.WhenAll(tasks);
                        }
                        catch (Exception ex)
                        {
                            tempModel_CampMember_ServiceContext.ErrorMessage += $"Task error: {ex.Message}";
                        }

                        tempModel_CampMember_ServiceContext.ErrorMessage += $"FFFF";

                        tempConfiguration_CampDating_ClientRequestResults.Main_CampDating_DataModel_FromServerx.Model_CampDating_ActualChatTargetFromDecryptioncsx =
                            new Model_CampDating_ActualChatTargetFromDecryptioncs
                            {
                                IncomingCaller = await hotCryptoService.EncryptWithCommonAgency(
                                    await hotCampCryptoAgency.DecryptwithAES(
                                        tempMain_CampDating_Request_FromClient.Main_CampDating_DataModel_FromClientx.Model_CampDating_CheckMessageTargetx.EncryptedCallerSHA)),
                                ActualEncrypedChatIDTarget = matchedEncryptedChatIDs
                            };

                        tempModel_CampMember_ServiceContext.ErrorMessage += $"GGGG";

                        tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                    }
                    catch (Exception ex)
                    {
                        tempModel_CampMember_ServiceContext.ErrorMessage += $"Camp_Dating_Service Model_CampDating_CheckMessageTargetx error : {ex.Message}";

                        tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(false);
                    }
                }

                //else if (tempMain_CampDating_Request_FromClient.Main_CDT_DataModel_FromClientx.Model_AssignCallerToReadAllx != null)
                //{
                //    try
                //    {
                //        CDT_SQL_Agency hotCDT_SQL_Agency = new CDT_SQL_Agency(User_Identifier, UserIdentifier256);

                //        await hotCDT_SQL_Agency.AssignCallerToReadAll(RecievedRequest.Main_CDT_DataModel_FromClientx.Model_AssignCallerToReadAllx);

                //        tempConfiguration_CDTClientRequestResults.Configuration_CDT_ServiceResultx.ServiceSuccessResult = new byte[] { 1 };
                //    }
                //    catch (Exception ex)
                //    {
                //        ServiceRequest.ErrorsMessages0 += ex.Message;
                //    }
                //}


                MainSW.Stop();

                tempModel_CampMember_ServiceContext.ErrorMessage += $"Camp_Dating_Service Elapse time: {MainSW.ElapsedMilliseconds} ms";

                tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages += tempModel_CampMember_ServiceContext.ErrorMessage;
                await hotBlob_Agency_CampMemberBlob.AppendCampMemberServerLogAsync(tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages);

                byte[] protobufData;
                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, tempConfiguration_CampDating_ClientRequestResults);
                    protobufData = stream.ToArray();
                }

                return protobufData;

            }
            catch (Exception ex)
            {
                tempModel_CampMember_ServiceContext.ErrorMessage += $"Camp_Dating_Service RunService error : {ex.Message}";



                tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages += tempModel_CampMember_ServiceContext.ErrorMessage;
                await hotBlob_Agency_CampMemberBlob.AppendCampMemberServerLogAsync(tempConfiguration_CampDating_ClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages);

                byte[] protobufData;
                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, tempConfiguration_CampDating_ClientRequestResults);
                    protobufData = stream.ToArray();
                }

                return protobufData;
            }
        }








        public string? AddParticipant(string? oldString, string addition)
        {
            if (string.IsNullOrWhiteSpace(addition))
                return oldString;

            var list = new List<string>();

            if (!string.IsNullOrWhiteSpace(oldString))
                list.AddRange(oldString.Split('X', StringSplitOptions.RemoveEmptyEntries));

            if (list.Contains(addition))
                return null;

            list.Add(addition);

            var sorted = list
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase) // A-Z, then numbers
                .ToList();

            return string.Join("X", sorted);
        }

        public string? RemoveParticipant(string? oldString, string nameToRemove)
        {
            if (string.IsNullOrWhiteSpace(oldString) || string.IsNullOrWhiteSpace(nameToRemove))
                return oldString;

            var parts = oldString
                .Split('X', StringSplitOptions.RemoveEmptyEntries)
                .Where(p => !p.Equals(nameToRemove, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (parts.Count == 0)
                return null;

            var sorted = parts
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToList();

            return string.Join("X", sorted);
        }

        public bool IsParticipantInList(string? participantList, string userId)
        {
            if (string.IsNullOrEmpty(participantList) || string.IsNullOrEmpty(userId))
                return false;

            var parts = participantList.Split('X', StringSplitOptions.RemoveEmptyEntries);
            return parts.Contains(userId);
        }

        public List<string> GetOtherParticipants(string allParticipants)
        {
            if (string.IsNullOrWhiteSpace(allParticipants) || string.IsNullOrWhiteSpace(tempModel_CampMember_ServiceContext.user_IdentifierSHAHEX))
                return new List<string>();

            return allParticipants
                .Split('X', StringSplitOptions.RemoveEmptyEntries)
                .Where(p => !p.Equals(tempModel_CampMember_ServiceContext.user_IdentifierSHAHEX, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        public int GetParticipantIndex1Based(string participantList, string hexUserId)
        {
            if (string.IsNullOrWhiteSpace(participantList) || string.IsNullOrWhiteSpace(hexUserId))
                return -1;

            var parts = participantList.Split('X', StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < parts.Length; i++)
            {
                if (parts[i].Equals(hexUserId, StringComparison.OrdinalIgnoreCase))
                    return i + 1; // 1-based index
            }
            return -1; // not found
        }

        public static List<string> GetAllParticipants(string participantString)
        {
            if (string.IsNullOrWhiteSpace(participantString))
                return new List<string>();

            return participantString
                .Split('X', StringSplitOptions.RemoveEmptyEntries)
                .ToList();
        }



        public static (double? PosX, double? PosY) LatLonToMercator(double? latitude, double? longitude)
        {
            if (latitude == null || longitude == null)
                return (null, null);

            const double R = 6378137; // Earth radius in meters
            double x = R * (Math.PI / 180) * longitude.Value;
            double y = R * Math.Log(Math.Tan(Math.PI / 4 + (Math.PI / 180) * latitude.Value / 2));
            return (x, y);
        }


    }
}