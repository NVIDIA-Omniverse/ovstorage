// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { ClientCapabilities, ServerCapabilities, Capabilities } from "@omniverse/idl/plugin/capabilities";

/**
 *                                     !!!! IMPORTANT !!!!
 * When parameters of interface function or returned type is changed, version of function must be updated!
 * IDL guideline: update function versions whenever an interface parameter or
 * returned type changes.
 */

type Version = "1.19"

interface Connection {
  ping(ts?: Timestamps): PingResponse;

  /**
   * Authorize
   * @version 5
   * At version 5
   *  In "Auth" response - "max_in_flight_requests" us added.
   *                     - SlowDown status added
   *                     - backoff_time_ms field is added
   *                     - slowDown opt-in param added
   * At version 4
   *  In "Auth" request - "userAgent" is added.
   * At version 3
   *  In "Auth" response - "multipart_chunk_size" is added.
   * At version 2
   *  In "Auth" response - "connection_id_signature" is added.
   * At version 1:
   *  In parameters - "client_capabilities" are added.
   *  In "Auth" response - "version", "server_capabilities" are added. New status - "TokenExpired".
   */
  auth(version: Version, client_capabilities?: ClientCapabilities<Connection>, username?: string, password?: string, token?: string, ssoCookie?: string, userAgent?: string, slowDown?: boolean): Auth;

  /**
   * Authorize with a token
   * @version 4
   * At version 4
   *  In "Auth" response - "max_in_flight_requests" us added.
   *                     - SlowDown status added
   *                     - backoff_time_ms field is added
   *                     - slowDown opt-in param added
   * At version 3:
   *  In "Auth" request - "userAgent" is added.
   * At version 2:
   *  In "Auth" response - "multipart_chunk_size" is added.
   * At version 1:
   *  In "Auth" response - "connection_id_signature" is added.
   */
  authorize_token(token: string, version: Version, client_capabilities: ClientCapabilities<Connection>, userAgent?: string, slowDown?: boolean): Auth;
  subscribe_server_notifications(): ServerNotificationResponse[];

  /*
   * Set user agent value
  */
  set_user_agent(userAgent: string): Response;

  /** 📁 Path **/
  /**
   * Stat a path
   * @version 2
   * At version 2:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  In response: "locked_by", "lock_time", "lock_owner", "lock_duration", "lock_etag" were added
  **/
  stat2(path: PathAtVersion): Stat2Result;

  /**
   * List directory by mask and be notified about changes.
   * @version 5
   * At version 5:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 4:
   *  In response: "locked_by", "lock_time", "lock_owner", "lock_duration", "lock_etag" were added
   * At version 3:
   *  In response: PARTIALLY_COMPLETED status returned in case early break
   * At version 2:
   *  In response: "destination", "created_date_seconds", "modified_date_seconds", "empty" fields are added. PathEvent::Rename is added.
   * At version 1:
   *  In response: "PathEvent::Options" is added. "transaction_id" is added.
   */
  list(uri: string, recursive: boolean, show_hidden: boolean, type?: PathType): Path[];

  /**
   * List paths in Omniverse, only directories can be listed, apply branch resolution rules

   * @version 5
   * At version 5:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 4:
   *  In response: added optional checkpoint_count field
   * At version 3:
   *  In request: show_hidden optional argument is added
   * At version 2:
   *  In response: PARTIALLY_COMPLETED status returned in case early break
   * At version 1:
   *  In response: "locked_by", "lock_time", "lock_owner", "lock_duration", "lock_etag" were added
  **/
  list2(
       /* Omniverse path to be listed */
       path: string,
       /* Branch list, if not specified or empty - means the default branch */
       branches?: string[],
       /* Optional path type. If unspecified all path types are listed. If specified a particular path type is listed. */
       path_types?: PathType[],
       /* Show hidden (aka 'system') paths, false by default */
       show_hidden?: boolean): List2Response[]

  /**
   * Subscribe to changes in a directory. Only directories are supported. Non-recursive subscriptions only.
   * @version 4
   * At version 4:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 3:
   *  In response: added handling for mounted paths
   * At version 2:
   *  In response: added return status QuotaReached in case there are to many subscriptions from the same connection
   * At version 1:
   *  In response: added optional checkpoint_count field and PathType::CheckpointsChanged event
   **/
  subscribe_list(path: PathAtBranch): SubscribeListResponse[]

  /**
   * Subscribe to all events. This function can only be used by superusers and it's meant for services.
   * @version 1
   * At version 1:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   **/
  service_subscribe_list(): ServiceSubscribeListResponse[]

  /**
   * Resolve ACLs for a given set of paths. ACLs are resolved with relation to the given principal (represented by JWT).
   * This function can only be used by superusers and it's meant for services.
   * @version 2
   * At version 2:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  In request parameters - the optional "no_stat_on_mount" flag is added.
   **/
  service_resolve_acl(jwt: string, paths: PathAtVersion[], no_stat_on_mount?: boolean): ServiceResolveAclResponse

  /**
   * Create a path
   * @deprecated This method is deprecated, use newer version (see create_[asset, object, directory])
   * @version 2
   * At version 2:
   *  In response - StatusType::NotObject is added.
   *  !!! IMPLICIT CHANGE !!! - "overwrite" parameter is fixed to work correctly with LFT
   * At version 1:
   *  In request parameters - optional "overwrite" flag is added.
   **/
  create(uri: string, content?: bytes, type?: PathTypeCode, content_id?: string, overwrite?: boolean): UploadResult;

  /**
   * Update a path
   * @deprecated This method is deprecated, use newer version (see update_[asset, object])
   * @version 1
   * At version 1:
   *  In response - StatusType::NotObject is added.
   */
  update(uri: string, etag?: string, delta?: string, content?: bytes, content_id?: string, ts?: Timestamps): UploadResult;

  /**
   * Create an asset
   * @version 2
   * At version 2:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  In request parameters - optional checkpoint "message" is added.
   */
  create_asset(path: PathAtBranch, content?: bytes, content_id?: uint64, overwrite?: boolean, message?: string): CreateAssetResult;
  /**
   * Update an asset
   * @version 2
   * At version 2:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  In request parameters - optional checkpoint "message" is added.
   */
  update_asset(path: PathAtBranch, etag?: string, delta?: string, content?: bytes, content_id?: uint64, ts?: Timestamps, message?: string): UpdateAssetResult;

  /**
   * Create an asset with hash
   * @version 2
   * At version 2:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  In request parameters - optional checkpoint "message" is added.
   */
  create_asset_with_hash(path: PathAtBranch, hash_value: string, hash_type: string, hash_bsize: uint64, overwrite?: boolean, message?: string): CreateAssetWithHashResult;
  /**
   * Update an asset with hash
   * @version 2
   * At version 2:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  In request parameters - optional checkpoint "message" is added.
   */
  update_asset_with_hash(path: PathAtBranch, hash_value: string, hash_type: string, hash_bsize: uint64, etag?: string, delta?: string, ts?: Timestamps, message?: string): UpdateAssetWithHashResult;

  /**
   * Create an object
   * @version 2
   * At version 2:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  In request parameters - optional checkpoint "message" is added.
   */
  create_object(path: PathAtBranch, content?: bytes, content_id?: uint64, overwrite?: boolean, message?: string): CreateObjectResult;
  /**
   * Update an object
   * @version 2
   * At version 2:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  In request parameters - optional checkpoint "message" is added.
   */
  update_object(path: PathAtBranch, object_id: uint64, content?: bytes, content_id?: uint64, ts?: Timestamps, message?: string): UpdateObjectResult;

  /**
   * Deep copy object structure without values
   */
  deep_copy_object_struct(src_path: PathAtVersion, dst_path: PathAtBranch) : DeepCopyObjectStructResult;

  /**
   * Read and subscribe for a path
   * @version 2
   * At version 2:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  In response: added return status QuotaReached in case there are to many subscriptions from the same connection
   */
  read(uri: string, etag?: string): ReadResult[];

  /**
   * Read for an asset with version
   */
  read_asset_version(path: PathAtVersion, etag?: string): ReadAssetVersionResult[];
  /**
   * Read for an asset in branches
   */
  read_asset_resolved(path: string, branches: string[]): ReadAssetResolvedResult[];
  /**
   * Read an asset and subscribe to further updates
   * @version 2
   * At version 2:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  In response: added return status QuotaReached in case there are to many subscriptions from the same connection
   */
  subscribe_read_asset(path: PathAtBranch, etag?: string): SubscribeReadAssetResult[];

  /**
   * Read an object with version
   */
  read_object_version(path: PathAtVersion, sequence?: uint64): ReadObjectVersionResult[];
  /**
   * Read an object in branches
   */
  read_object_resolved(path: string, branches: string[]): ReadObjectResolvedResult[];

  /**
   * Read an object and subscribe to further updates
   * @version 3
   * At version 3:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 2:
   *  In response: added return status QuotaReached in case there are to many subscriptions from the same connection
   * At version 1:
   *  In parameters - "values_sequence" is added (it was subsequently removed without bumping the version, since it wasn't used by any clients)
   */
  subscribe_read_object(path: PathAtBranch, object_id?: uint64, sequence?: uint64): SubscribeReadObjectResult[];

  /**
   * Rename a path
   * @version 2
   * At version 2:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  Fixed rename request - disallow rename if destination with same name but different type already exist
   **/
  rename(source_and_destination: SourceDestinationPair[], branch?: string): MoveResponse;

  /**
   * Rename a path
   * @version 1
   * At version 1:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   **/
  rename2(paths_to_rename: PathsToRename[]): MoveResponse;

  /**
   * @deprecated This method is deprecated, use newer version (see delete2)
   * Delete a path
   **/
  delete(uri: string): DeletedPath[];

  /**
   * Delete a path, doesn't support recursive removal, doesn't support wildcards
   * Supports branches / checkpoints
   * Only empty folders can be removed
   * @version 1
   * At version 1:
   *  In reponse - SlowDown status added
   *              - backoff_time_ms field is added
   **/
  delete2(paths_to_delete: PathAtVersion[]): Delete2Response;

  /**
   * Copy a path, doesn't support recursive removal, doesn't support wildcards
   * Supports branches / checkpoints
   * Only files could be copied
   * Doesn't support mounts as source
   * @version 2
   * At version 2:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  In request parameters - optional checkpoint "message" is added to PathsToCopy.
   **/
  copy2(paths_to_copy: PathsToCopy[]): Copy2Response;

  /**
   * Create a directory
   * @version 1
   * At version 1:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   **/
  create_directory(path: PathAtBranch): CreateDirectoryResult;

  /**
   * Lock an asset
   * @version 3
   * At version 3:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 2:
   *  Versioning supported - optional "branch" parameter is added.
   * At version 1:
   *  In response - optional "etag" field is added.
   *  !!!IMPLICIT CHANGE!!! When "etag" is '0' - server uses latest etag
   **/
  lock(uri: string, etag: string, duration?: uint64, branch?: string): LockResult;

  /**
   * Unlock an asset
   * @version 2
   * At version 2:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  Versioning supported - optional "branch" parameter is added.
   **/
  unlock(uri: string, force?: boolean, branch?: string): UnlockResult;

  /**
   * Copy a path
   * @version 2
   * At version 2:
   *  In respone - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  !!!IMPLICIT CHANGE!!! When transaction_id is '0' - server uses latest transaction_id
   **/
  copy(uri: string, to: string, transaction_id: string): CopyResult;
  get_transaction_id(): TransactionIDResult;

  /**
   * Set path options
   * @deprecated This method is deprecated. Use 'set_path_options_v2' instead
   * @version 1
   * At version 1:
   *  Versioning support - optional "branch" and "checkpoint" parameters are added.
   **/
  set_path_options(uri: string, created_by?: string, modified_by?: string, created?: string, modified?: string, branch?: string, checkpoint?: uint64): SetPathOptionsResult;

  /**
   * Sets path options by using 'uint64' type of fields, which means 'seconds from Epoch'
   */
  set_path_options2(path: string, created_by?: string, modified_by?: string, created?: uint64, modified?: uint64, branch?: string, checkpoint?: uint64): SetPathOptionsResult;

  /** 🔒 Permissions **/
  get_acl(uri: string): ACLResult;
  change_acl(uri: string, acl: ACL): ResponseWithUri;

  get_acl_v2(paths: PathAtVersion[]): GetACLResponses;
  /**
   * Returns resolved ACLs for a given set of paths.
   * Resolved ACLs take into the account rules of ACL inheritance.
   */
  get_acl_resolved(paths: PathAtVersion[]): GetACLResolvedResponses;
  set_acl_v2(path_and_acls: PathAtVersionACLPair[]): SetACLResponse;

  /** 👥 User Management **/
  get_groups(): GroupList;
  get_group_users(group_name: string): GetGroupUsersResponse;
  get_users(): UserList;
  get_user_groups(username: string): GetUserGroupsResponse;
  create_group(group_name: string): CreateGroupResponse;
  rename_group(group_name: string, new_group_name: string): RenameGroupResponse;
  remove_group(group_name: string): RemoveGroupResponse;
  add_user_to_group(username: string, group_name: string): AddUserToGroupResponse;
  remove_user_from_group(username: string, group_name: string): RemoveUserFromGroupResponse;

  /** 💻 Mounts **/
  mount(uri: string, resolver?: string, redirect_url?: string, options?: JSONString): ResponseWithUri;
  unmount(uri: string): ResponseWithUri;
  get_mount_info(): MountsInfo;

  /** Versioning **/
  /**
   * Create a checkpoint
   * @version 2
   * At version 2:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   * At version 1:
   *  added 'force' flag, which makes the server generate the checkpoint anyway, even if the path is
   *  already checkpointed
   **/
  checkpoint_version(path: PathAtBranch, message?: string, force?: boolean): CheckpointVersionResponse;

  /**
   * Replace destination path at branch with source
   * @version 1
   * At version 1:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   **/
  replace_version(src_path: PathAtVersion, dst_path: PathAtBranch, message?: string): Response;

  /**
   * Get all checkpoints
   * @version 1
   * At version 1:
   *  In response - SlowDown status added
   *              - backoff_time_ms field is added
   **/
  get_checkpoints(path: PathAtBranch): GetCheckpointsResponse;

  /**
   * Get all branches for path
   * @version 1
   * At version 1:
   *  In response - SlowDown status
   *              - backoff_time_ms field is added
   **/
  get_branches(path: string): GetBranchesResponse;
}

enum StatusType {
  OK = "OK",
  Done = "DONE",
  Idle = "IDLE",
  Denied = "DENIED",
  Latest = "LATEST",
  InvalidCommand = "INVALID_COMMAND",
  InvalidPath = "INVALID_URI",
  Unauthenticated = "UNAUTHENTICATED",
  ContentLengthMismatch = "CONTENT_LENGTH_MISMATCH",
  AlreadyExists = "ALREADY_EXISTS",
  NotImplemented = "NOT_IMPLEMENTED",
  ResourceBusy = "RESOURCE_BUSY",
  NotAsset = "NOT_ASSET",
  InternalError = "INTERNAL_ERROR",
  IncompatibleVersion = "INVALID_VERSION",
  InvalidETag = "INVALID_ETAG",
  InvalidTransactionId = "INVALID_TRANSACTION_ID",
  AccessLost = "ACCESS_LOST",
  ConnectionLost = "CONNECTION_LOST",
  UnknownStatus = "UNKNOWN_STATUS",
  Timeout = "TIMEOUT",
  OperationFailed = "OPERATION_FAILED",
  BufferTooSmall = "BUFFER_TOO_SMALL",
  ContentBufferOverflow = "CONTENT_BUFFER_OVERFLOW",
  InvalidParameters = "INVALID_PARAMETERS",
  NotInitialized = "NOT_INITIALIZED",
  AlreadyAuthenticated = "ALREADY_AUTHENTICATED",
  InvalidContentId = "INVALID_CONTENT_ID",
  UserNotFound = "USER_NOT_FOUND",
  GroupNotFound = "GROUP_NOT_FOUND",
  GroupAlreadyExists = "GROUP_ALREADY_EXISTS",
  UserNotInGroup = "USER_NOT_IN_GROUP",
  UserAlreadyInGroup = "USER_ALREADY_IN_GROUP",
  MountExistsUnderPath = "MOUNT_EXISTS_UNDER_PATH",
  TokenExpired = "TOKEN_EXPIRED",
  NotExist = "NOT_EXIST",
  FolderNotEmpty = "FOLDER_NOT_EMPTY",
  NotObject = "NOT_OBJECT",
  PartiallyCompleted = "PARTIALLY_COMPLETED",
  QuotaReached = "QUOTA_REACHED",
  SlowDown = "SLOW_DOWN"
}

type TimestampMicroseconds = uint64

type StringPair =
{
    key: string
    value: string
}

type SourceDestinationPair = StringPair

type PathsToCopy = {
    src: PathAtVersion
    dst: PathAtBranch
    message?: string
}

type PathsToRename = {
    src: PathAtBranch
    dst: PathAtBranch
    message?: string
}

type PathAtBranch = {
  path: string
  branch?: string
}

type PathAtVersion = {
  path: string
  branch?: string
  checkpoint?: uint64
}

type Timestamps = {
  [key:string]:TimestampMicroseconds;
}

type Response = {
  status: StatusType;
  ts: Timestamps;
  backoff_time_ms?: uint64;
};

type MoveResponse =
{
    status: StatusType;
    ts: Timestamps;
    responses: StatusType[];
    backoff_time_ms?: uint64;
}

type PingResponse = {
  status: StatusType;
  ts?: Timestamps;
  auth?: string;
  username?: string;
  token?: string;
  connection_id?: string;
  max_chunk_size?: uint64;
  version?: string;
  backoff_time_ms?: uint64;
}

/** 🔑 Authentication **/
type Auth = {
  status: StatusType;
  server_capabilities?: ServerCapabilities<Connection>;
  ts?: Timestamps;
  version?: string;
  username: string;
  token: string;
  connection_id: string;
  connection_id_signature?: string;
  max_chunk_size: uint64;
  lft_address?: string;
  lft_threshold?: uint64;
  super_user?: boolean;
  multipart_chunk_size?: uint64;
  max_in_flight_requests?: uint64;
  backoff_time_ms?: uint64;
}

/** 📁 Path **/
type UploadResult = {
  status: StatusType;
  ts?: Timestamps;
  uri?: string;
  etag?: string;
  type?: PathType;
  transaction_id?: string;
  hash_type?: string;
  hash_value?: string;
  hash_bsize?: uint64;
  backoff_time_ms?: uint64;
}

type CreateAssetWithHashResult = {
  status: StatusType;
  ts?: Timestamps;
  etag?: string;
  transaction_id?: uint64;
  hash_type?: string;
  hash_value?: string;
  hash_bsize?: uint64;
  backoff_time_ms?: uint64;
}

type UpdateAssetWithHashResult = {
  status: StatusType;
  ts?: Timestamps;
  etag?: string;
  transaction_id?: uint64;
  hash_type?: string;
  hash_value?: string;
  hash_bsize?: uint64;
  backoff_time_ms?: uint64;
}

type CreateAssetResult = {
  status: StatusType;
  ts?: Timestamps;
  etag?: string;
  transaction_id?: uint64;
  hash_type?: string;
  hash_value?: string;
  hash_bsize?: uint64;
  backoff_time_ms?: uint64;
}

type UpdateAssetResult = {
  status: StatusType;
  ts?: Timestamps;
  etag?: string;
  transaction_id?: uint64;
  hash_type?: string;
  hash_value?: string;
  hash_bsize?: uint64;
  backoff_time_ms?: uint64;
}

type CreateObjectResult = {
  status: StatusType;
  sequence?: uint64;
  object_id?: uint64;
  ts?: Timestamps;
  transaction_id?: uint64;
  backoff_time_ms?: uint64;
}

type UpdateObjectResult = {
  status: StatusType;
  sequence?: uint64;
  ts?: Timestamps;
  transaction_id?: uint64;
  backoff_time_ms?: uint64;
}

type DeepCopyObjectStructResult = {
  status: StatusType;
  sequence?: uint64;
  ts?: Timestamps;
  transaction_id?: string;
  backoff_time_ms?: uint64;
}

type Path = {
  status: StatusType;
  ts?: Timestamps;
  type?: PathType;
  uri?: string;
  destination?: string;
  acl?: PathPermission[];
  created?: string;
  created_date_seconds?: uint64;
  created_by?: string;
  modified?: string;
  modified_date_seconds?: uint64;
  modified_by?: string;
  size?: uint64;
  etag?: string;
  event?: PathEvent;
  empty?: boolean;
  mounted?: boolean;
  transaction_id?: string;
  hash_type?: string;
  hash_value?: string;
  hash_bsize?: uint64;
  locked_by?: string;
  lock_time?: uint64;
  lock_owner?: string;
  lock_duration?: float;
  lock_etag?: string;
  backoff_time_ms?: uint64;
}

type List2ResponsePathEntry =
{
  path?: string;
  branch?: string;
  etag?: string;
  acl?: PathPermission[];
  created_timestamp?: uint64;
  modified_timestamp?: uint64;
  path_type?: PathType;
  size?: uint64;
  empty?: boolean;
  mounted?: boolean;
  created_by?: string;
  modified_by?: string;
  hash_type?: string;
  hash_value?: string;
  hash_bsize?: uint64;
  checkpointed?: boolean;
  destination?: string;
  transaction_id?: uint64;
  locked_by?: string;
  lock_time?: uint64;
  lock_owner?: string;
  lock_duration?: float;
  lock_etag?: string;
  checkpoint_count?: uint64;
}

type List2Response = {
  status: StatusType;
  ts?: Timestamps;
  entries?: List2ResponsePathEntry[];
  backoff_time_ms?: uint64;
}

type SubscribeListResponse = {
  status: StatusType;
  ts?: Timestamps;
  event?: PathEvent;
  entry?: List2ResponsePathEntry;
  backoff_time_ms?: uint64;
}

type ServiceSubscribeListResponse = {
  status: StatusType;
  ts?: Timestamps;
  event?: PathEvent;
  entry?: List2ResponsePathEntry;
  backoff_time_ms?: uint64;
}

type ServiceResolveResponseAclEntry = {
  status?: StatusType;
  acl?: PathPermission[];
  backoff_time_ms?: uint64;
}

type ServiceResolveAclResponse = {
  status: StatusType;
  ts?: Timestamps;
  entries?: ServiceResolveResponseAclEntry[];
  backoff_time_ms?: uint64;
}

type Stat2Result = {
  status: StatusType;
  ts?: Timestamps;
  type?: PathType;
  uri?: string;
  acl?: PathPermission[];
  created?: string;
  created_date_seconds?: uint64;
  created_by?: string;
  modified?: string;
  modified_date_seconds?: uint64;
  modified_by?: string;
  mounted?: boolean;
  empty?: boolean;
  size?: uint64;
  etag?: string;
  transaction_id?: string;
  hash_type?: string;
  hash_value?: string;
  hash_bsize?: uint64;
  checkpointed?: boolean;
  locked_by?: string;
  lock_time?: uint64;
  lock_owner?: string;
  lock_duration?: float;
  lock_etag?: string;
  backoff_time_ms?: uint64;
}

type DeletedPath = {
  status: StatusType;
  ts?: Timestamps;
  uri?: string;
  acl?: PathPermission[];
  type?: PathType;
  transaction_id?: string;
  backoff_time_ms?: uint64;
}

type Delete2Response = {
  status: StatusType;
  ts?: Timestamps;
  responses: StatusType[];
  backoff_time_ms?: uint64;
}

type UndeleteResponse = {
  status: StatusType;
  ts?: Timestamps;
  responses?: StatusType[]
  transaction_ids?: uint64[];
  backoff_time_ms?: uint64;
}

type ObliterateResponse = {
  status: StatusType;
  ts?: Timestamps;
  responses?: StatusType[];
  backoff_time_ms?: uint64;
}

type Copy2Response = {
  status: StatusType;
  ts: Timestamps;
  responses: StatusType[];
  backoff_time_ms?: uint64;
}

type ReadResult = {
  status: StatusType;
  ts?: Timestamps;
  etag?: string;
  delta?: string;
  content?: bytes;
  uri_redirection?: string;
  hash_value?: string;
  hash_type?: string;
  hash_bsize?: uint64;
  size?: uint64;
  transaction_id?: string;
  uri?: string;
  backoff_time_ms?: uint64;
}

type ReadAssetVersionResult =  {
  status: StatusType;
  ts?: Timestamps;
  etag?: string;
  delta?: string;
  content?: bytes;
  uri_redirection?: string;
  hash_value?: string;
  hash_type?: string;
  hash_bsize?: uint64;
  size?: uint64;
  transaction_id?: uint64;
  backoff_time_ms?: uint64;
}

type SubscribeReadObjectResult = {
  status: StatusType;
  ts?: Timestamps;
  sequence?: uint64;
  content?: bytes;
  uri_redirection?: string;
  size?: uint64;
  object_id?: uint64;
  backoff_time_ms?: uint64;
}

type SubscribeReadAssetResult = {
  status: StatusType;
  ts?: Timestamps;
  etag?: string;
  delta?: string;
  content?: bytes;
  uri_redirection?: string;
  hash_value?: string;
  hash_type?: string;
  hash_bsize?: uint64;
  size?: uint64;
  transaction_id?: uint64;
  backoff_time_ms?: uint64;
}

type ReadObjectVersionResult =  {
  status: StatusType;
  sequence?: uint64;
  ts?: Timestamps;
  content?: bytes;
  size?: uint64;
  uri_redirection?: string;
  backoff_time_ms?: uint64;
}

type ReadObjectResolvedResult =  {
  status: StatusType;
  sequence?: uint64;
  branch?: string;
  ts?: Timestamps;
  content?: bytes;
  size?: uint64;
  uri_redirection?: string;
  backoff_time_ms?: uint64;
}

type ReadAssetResolvedResult =  {
  status: StatusType;
  branch?: string;
  ts?: Timestamps;
  etag?: string;
  delta?: string;
  content?: bytes;
  uri_redirection?: string;
  hash_value?: string;
  hash_type?: string;
  hash_bsize?: uint64;
  size?: uint64;
  transaction_id?: uint64;
  backoff_time_ms?: uint64;
}

enum PathType {
  Any = "none",
  Asset = "asset",
  Folder = "folder",
  Channel = "channel",
  Mount = "mount",
  Object = "omniobject"
}

enum PathTypeCode {
  Any = 0,
  Asset = 1,
  Folder = 2,
  Channel = 3,
  Object = 4,
  Mount = 5
}

enum PathEvent {
  Full = "full",
  Create = "create",
  Delete = "delete",
  Delta = "delta",
  ChangeAcl = "change_acl",
  Options = "set_path_options",
  Locked = "lock",
  Unlocked = "unlock",
  Rename = "rename",
  Copy = "copy",
  VersionReplaced = "replace_version",
  CheckpointsChanged = "checkpoints_changed"
}

enum PathPermission {
  Read = "read",
  Write = "write",
  Admin = "admin"
}

type FullUpdateEtag = ""

type CreateDirectoryResult =
{
  status: StatusType;
  ts: Timestamps;
  backoff_time_ms?: uint64;
}

type LockResult = {
  status: StatusType;
  ts?: Timestamps;
  etag?: string;
  uri?: string;
  backoff_time_ms?: uint64;
}

type UnlockResult = {
  status: StatusType;
  ts: Timestamps;
  etag?: string;
  uri?: string;
  backoff_time_ms?: uint64;
}

type ACLResult = {
  status: StatusType;
  ts: Timestamps;
  acl?: ACL;
  backoff_time_ms?: uint64;
}

type ACL = {
  [userOrGroup: string]: PathPermission[];
}

type ACLAtLevelValue = {
  acl: PathPermission[];
  path: string
  /**
   * This field tells due to which group the ACLs might
   * have been modified. E.g. in case 'user' has only read access
   * but 'users' group to which he belongs has read-write access,
   * then this field will be equal to 'users' and that lets the
   * client know why 'user' has read-write access in the end
   * (because 'users' group has)
   **/
  group?: string
}

type ACLAtLevel = {
  [userOrGroup: string]: ACLAtLevelValue;
}

type GetACLResponse
{
  status: StatusType;
  acl?: ACL;
  backoff_time_ms?: uint64;
}

type GetACLResolvedResponse
{
  status: StatusType;
  acl?: ACLAtLevel;
  backoff_time_ms?: uint64;
}

// Omniverse path permission types
type GetACLResponses = {
    ts: Timestamps;
    status: StatusType;
    responses: GetACLResponse[];
    backoff_time_ms?: uint64;
}

type GetACLResolvedResponses = {
    ts: Timestamps;
    status: StatusType;
    responses: GetACLResolvedResponse[];
    backoff_time_ms?: uint64;
}

type PathAtVersionACLPair
{
   path_at_version: PathAtVersion
   acl: ACL
}

type SetACLResponse = {
    ts: Timestamps;
    status: StatusType;
    pathStatuses: StatusType[];
    backoff_time_ms?: uint64;
}

type CopyResult = {
  status: StatusType;
  ts: Timestamps;
  uri?: string;
  transaction_id?: string;
  num_copied?: string;
  backoff_time_ms?: uint64;
}

type TransactionIDResult = {
  status: StatusType;
  ts: Timestamps;
  transaction_id?: uint64;
  backoff_time_ms?: uint64;
}

type SetPathOptionsResult = {
  status: StatusType;
  ts: Timestamps;
  backoff_time_ms?: uint64;
}

/** 👥 User Management **/
type GroupList = {
  status: StatusType;
  ts: Timestamps;
  groups?: string[];
  backoff_time_ms?: uint64;
}

type UserList = {
  status: StatusType;
  ts: Timestamps;
  users?: string[];
  backoff_time_ms?: uint64;
}

type CheckpointVersionResponse =
{
  status: StatusType;
  ts: Timestamps;
  path: string;
  branch: string;
  checkpoint: uint64;
  backoff_time_ms?: uint64;
}

/** 💻 Mounts **/
type MountsInfo = {
  status: StatusType;
  ts?: Timestamps;
  mounts: MountInfo[];
  backoff_time_ms?: uint64;
}

type MountInfo = {
    uri: string;
    redirect_url?: string;
    resolver?: string;
    options?: JSONString;
}

enum NotificationLevel
{
    Info="INFO",
    Warning="WARNING",
    Critical="CRITICAL"
}

type ServerNotificationResponse =
{
    status: StatusType,
    ts: Timestamps,
    level?: NotificationLevel,
    notification?: string,
    backoff_time_ms?: uint64
}

type JSONString = string


interface ServerFeatures {
    exchange_capabilities(client_capabilities: ClientCapabilities<ServerFeatures>): CapabilitiesResponse;

    omni_objects(): OmniObjectsResponse;
    omni_objects2(): OmniObjects2Response;
    lft(): LftResponse;
    hashes(): HashesResponse;
    versioning(): VersioningResponse;
}

type CapabilitiesResponse = {
    status: StatusType;
    server_capabilities: ServerCapabilities<ServerFeatures>;
    backoff_time_ms?: uint64;
}

type OmniObjectsResponse = {
    status: StatusType;
    enabled?: boolean;
    ext_value_min_size?: uint64;
    backoff_time_ms?: uint64;
}

type OmniObjects2Response = {
    status: StatusType;
    ext_value_min_size?: uint64;
    backoff_time_ms?: uint64;
}

type LftResponse = {
    status: StatusType;
    lft_server_path?: string;
    upload_threshold?: uint64;
    backoff_time_ms?: uint64;
}

type HashesResponse = {
    status: StatusType;
    types?: HashType[];
    backoff_time_ms?: uint64;
}

type VersioningResponse = {
    status: StatusType;
    enabled?: boolean;
    backoff_time_ms?: uint64;
}

type HashType = {
    type: string;
    block_size: uint64;
}

type Checkpoint =
{
    status: StatusType;
    checkpoint_id?: uint64;
    message?:string;
    backoff_time_ms?: uint64;
}

type GetCheckpointsResponse =
{
    status: StatusType;
    checkpoints: Checkpoint[];
    backoff_time_ms?: uint64;
}

type GetBranchesResponse =
{
    status: StatusType;
    branches: string[];
    backoff_time_ms?: uint64;
}

type GetGroupUsersResponse =
{
  status: StatusType;
  ts: Timestamps;
  group?: string;
  users: string[];
  backoff_time_ms?: uint64;
}

type GetUserGroupsResponse =
{
  status: StatusType;
  ts: Timestamps;
  username?: string;
  groups: string[];
  backoff_time_ms?: uint64;
}

type RenameGroupResponse =
{
  status: StatusType;
  ts: Timestamps;
  group?: string;
  new_group?: string;
  backoff_time_ms?: uint64;
}

type CreateGroupResponse =
{
  status: StatusType;
  ts: Timestamps;
  group?: string;
  backoff_time_ms?: uint64;
}

type RemoveGroupResponse =
{
  status: StatusType;
  ts: Timestamps;
  group?: string;
  change_count?: uint64;
  backoff_time_ms?: uint64;
}


type AddUserToGroupResponse =
{
  status: StatusType;
  ts: Timestamps;
  username?: string;
  group?: string;
  backoff_time_ms?: uint64;
}

type RemoveUserFromGroupResponse =
{
  status: StatusType;
  ts: Timestamps;
  username?: string;
  group?: string;
  backoff_time_ms?: uint64;
}

type ResponseWithUri =
{
  status: StatusType;
  ts: Timestamps;
  uri?: string;
  backoff_time_ms?: uint64;
}
