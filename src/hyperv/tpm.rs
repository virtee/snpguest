// SPDX-License-Identifier: Apache-2.0
// This file contains code for handling TPM 2.0.

use anyhow::{Context, Result};
use tss_esapi::{
    abstraction::nv,
    attributes::NvIndexAttributesBuilder,
    handles::{NvIndexHandle, NvIndexTpmHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        resource_handles::{NvAuth, Provision},
    },
    structures::{MaxNvBuffer, Name, NvPublic, NvPublicBuilder},
};

/// Find an NV index
pub fn find_nv_index(
    ctx: &mut tss_esapi::Context,
    nv_index: NvIndexTpmHandle,
) -> Result<Option<(NvPublic, Name)>> {
    let list = nv::list(ctx).context("unable to list NV indices")?;

    let entry = list
        .into_iter()
        .find(|(public, _)| public.nv_index() == nv_index);

    Ok(entry)
}

/// Define a new NV index with the specified size
pub fn nv_define(
    ctx: &mut tss_esapi::Context,
    handle: NvIndexTpmHandle,
    len: usize,
) -> Result<NvIndexHandle> {
    let attributes = NvIndexAttributesBuilder::new()
        .with_owner_read(true)
        .with_owner_write(true)
        .build()
        .context("unable to build NV index attributes")?;

    let nv_public = NvPublicBuilder::new()
        .with_nv_index(handle)
        .with_index_attributes(attributes)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_data_area_size(len)
        .build()
        .context("unable to build NV public structure")?;

    let index = ctx
        .nv_define_space(Provision::Owner, None, nv_public)
        .context("unable to define NV index")?;

    Ok(index)
}

/// Undefine an existing NV index
pub fn nv_undefine(ctx: &mut tss_esapi::Context, handle: NvIndexTpmHandle) -> Result<()> {
    let key_handle = ctx
        .execute_without_session(|c| c.tr_from_tpm_public(handle.into()))
        .context("unable to resolve NV index handle")?;
    let index = key_handle.into();
    ctx.nv_undefine_space(Provision::Owner, index)
        .context("unable to undefine NV index")
}

/// Write data to an NV index
pub fn nv_write(ctx: &mut tss_esapi::Context, handle: NvIndexTpmHandle, data: &[u8]) -> Result<()> {
    let buffer = MaxNvBuffer::try_from(data).context("unable to create MaxNvBuffer from data")?;
    let key_handle = ctx
        .execute_without_session(|c| c.tr_from_tpm_public(handle.into()))
        .context("unable to resolve NV index handle")?;
    let index = key_handle.into();
    ctx.nv_write(NvAuth::Owner, index, buffer, 0)
        .context("unable to write data to NV index")
}
