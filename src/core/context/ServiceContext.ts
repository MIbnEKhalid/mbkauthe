/**
 * MBKAuthe — ServiceContext Domain Model
 * Context representation for Machine-to-Machine (M2M) authenticated services.
 * Copyright (c) 2026 Muhammad Bin Khalid, MBKTech.org and contributors
 * Licensed under the MIT License.
 */

export interface ServiceContextOptions {
  serviceId: string;
  displayName?: string;
  allowedChannels?: string[];
  ipWhitelist?: string[];
}

export class ServiceContext {
  public readonly isService: true = true;
  public readonly serviceId: string;
  public readonly displayName: string;
  public readonly allowedChannels: string[];
  public readonly ipWhitelist: string[];

  constructor({
    serviceId,
    displayName,
    allowedChannels,
    ipWhitelist,
  }: ServiceContextOptions) {
    this.serviceId = String(serviceId || "").trim();
    this.displayName = displayName ? String(displayName).trim() : this.serviceId;
    this.allowedChannels =
      Array.isArray(allowedChannels) && allowedChannels.length
        ? allowedChannels.map((c) => String(c).trim())
        : ["*"];
    this.ipWhitelist =
      Array.isArray(ipWhitelist) && ipWhitelist.length
        ? ipWhitelist.map((ip) => String(ip).trim()).filter(Boolean)
        : [];
  }

  isChannelAllowed(channelKey: string): boolean {
    if (this.allowedChannels.includes("*")) return true;
    const target = String(channelKey || "").trim().toLowerCase();
    return this.allowedChannels.some((c) => c.toLowerCase() === target);
  }
}

