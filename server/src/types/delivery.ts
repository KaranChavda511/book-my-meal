// src/types/delivery.ts
export type DeliveryStatus = "assigned" | "picked_up" | "delivered" | "failed";

export interface IDelivery {
  id: string;
  orderId: string;
  deliveryPersonId: string; // userId with role=delivery
  status: DeliveryStatus;
  estimatedTime?: Date;
  createdAt?: Date;
  updatedAt?: Date;
}
