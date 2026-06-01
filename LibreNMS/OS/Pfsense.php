<?php

/*
 * Pfsense.php
 *
 * -Description-
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * @package    LibreNMS
 * @link       https://www.librenms.org
 * @copyright  2020 Tony Murray
 * @author     Tony Murray <murraytony@gmail.com>
 */

namespace LibreNMS\OS;

use App\Models\Device;
use LibreNMS\Interfaces\Data\DataStorageInterface;
use LibreNMS\Interfaces\Polling\OSPolling;
use LibreNMS\OS\Shared\Unix;
use LibreNMS\RRD\RrdDefinition;

class Pfsense extends Unix implements OSPolling
{
    private const HOST_RESOURCES_CPU_DEVICE_INDEX = 196608;
    private const HOST_RESOURCES_PFSENSE_PACKAGE_INDEX = 200;

    public function discoverOS(Device $device): void
    {
        parent::discoverOS($device);

        $this->discoverVersionFromPackages($device);
        $this->discoverHardwareFromHostResources($device);
    }

    private function discoverVersionFromPackages(Device $device): void
    {
        if (! empty($device->version) && ! $this->normalizePfsenseVersion($device->version)) {
            return;
        }

        $version = $this->validSnmpValue(snmp_get($this->getDeviceArray(), 'HOST-RESOURCES-MIB::hrSWInstalledName.' . self::HOST_RESOURCES_PFSENSE_PACKAGE_INDEX, '-Oqv'));
        $version = $this->normalizePfsenseVersion($version);
        if ($version !== null) {
            $device->version = $version;

            return;
        }

        foreach (snmpwalk_cache_oid($this->getDeviceArray(), 'hrSWInstalledName', [], 'HOST-RESOURCES-MIB') as $package) {
            $version = $this->normalizePfsenseVersion($package['hrSWInstalledName'] ?? null);
            if ($version !== null) {
                $device->version = $version;

                return;
            }
        }
    }

    private function discoverHardwareFromHostResources(Device $device): void
    {
        if (! empty($device->hardware) && ! $this->isArchitectureOnlyHardware($device->hardware)) {
            return;
        }

        $hardware = $this->validSnmpValue(snmp_get($this->getDeviceArray(), 'HOST-RESOURCES-MIB::hrDeviceDescr.' . self::HOST_RESOURCES_CPU_DEVICE_INDEX, '-Oqv'));
        if ($hardware !== null) {
            $device->hardware = $hardware;
        }
    }

    private function isArchitectureOnlyHardware(string $hardware): bool
    {
        return preg_match('/^(?:aarch64|alpha|amd64|arm\w*|i386|ia64|mips\w*|pc98|powerpc\w*|risc\w*|sparc\w*)$/i', trim($hardware)) === 1;
    }

    private function normalizePfsenseVersion(string|false|null $version): ?string
    {
        $version = $this->validSnmpValue($version);

        if ($version !== null && preg_match('/^pfSense(?:-base)?-(?<version>\d+(?:\.\d+)+.*)$/', $version, $matches)) {
            return $matches['version'];
        }

        return null;
    }

    private function validSnmpValue(string|false|null $value): ?string
    {
        $value = trim((string) $value, "\" \n\r\t");

        if ($value === '' || str_contains($value, 'No Such') || str_contains($value, 'No more variables left')) {
            return null;
        }

        return $value;
    }

    public function pollOS(DataStorageInterface $datastore): void
    {
        $oids = snmp_get_multi($this->getDeviceArray(), [
            'pfStateTableCount.0',
            'pfStateTableSearches.0',
            'pfStateTableInserts.0',
            'pfStateTableRemovals.0',
            'pfCounterMatch.0',
            'pfCounterBadOffset.0',
            'pfCounterFragment.0',
            'pfCounterShort.0',
            'pfCounterNormalize.0',
            'pfCounterMemDrop.0',
        ], '-OQUs', 'BEGEMOT-PF-MIB');

        if (is_numeric($oids[0]['pfStateTableCount'] ?? null)) {
            $rrd_def = RrdDefinition::make()->addDataset('states', 'GAUGE', 0);

            $fields = [
                'states' => $oids[0]['pfStateTableCount'],
            ];

            $tags = ['rrd_def' => $rrd_def];
            $datastore->put($this->getDeviceArray(), 'pf_states', $tags, $fields);

            $this->enableGraph('pf_states');
        }

        if (is_numeric($oids[0]['pfStateTableSearches'] ?? null)) {
            $rrd_def = RrdDefinition::make()->addDataset('searches', 'COUNTER', 0);

            $fields = [
                'searches' => $oids[0]['pfStateTableSearches'],
            ];

            $tags = ['rrd_def' => $rrd_def];
            $datastore->put($this->getDeviceArray(), 'pf_searches', $tags, $fields);

            $this->enableGraph('pf_searches');
        }

        if (is_numeric($oids[0]['pfStateTableInserts'] ?? null)) {
            $rrd_def = RrdDefinition::make()->addDataset('inserts', 'COUNTER', 0);

            $fields = [
                'inserts' => $oids[0]['pfStateTableInserts'],
            ];

            $tags = ['rrd_def' => $rrd_def];
            $datastore->put($this->getDeviceArray(), 'pf_inserts', $tags, $fields);

            $this->enableGraph('pf_inserts');
        }

        if (is_numeric($oids[0]['pfStateTableRemovals'] ?? null)) {
            $rrd_def = RrdDefinition::make()->addDataset('removals', 'COUNTER', 0);

            $fields = [
                'removals' => $oids[0]['pfStateTableRemovals'],
            ];

            $tags = ['rrd_def' => $rrd_def];
            $datastore->put($this->getDeviceArray(), 'pf_removals', $tags, $fields);

            $this->enableGraph('pf_removals');
        }

        if (is_numeric($oids[0]['pfCounterMatch'] ?? null)) {
            $rrd_def = RrdDefinition::make()->addDataset('matches', 'COUNTER', 0);

            $fields = [
                'matches' => $oids[0]['pfCounterMatch'],
            ];

            $tags = ['rrd_def' => $rrd_def];
            $datastore->put($this->getDeviceArray(), 'pf_matches', $tags, $fields);

            $this->enableGraph('pf_matches');
        }

        if (is_numeric($oids[0]['pfCounterBadOffset'] ?? null)) {
            $rrd_def = RrdDefinition::make()->addDataset('badoffset', 'COUNTER', 0);

            $fields = [
                'badoffset' => $oids[0]['pfCounterBadOffset'],
            ];

            $tags = ['rrd_def' => $rrd_def];
            $datastore->put($this->getDeviceArray(), 'pf_badoffset', $tags, $fields);

            $this->enableGraph('pf_badoffset');
        }

        if (is_numeric($oids[0]['pfCounterFragment'] ?? null)) {
            $rrd_def = RrdDefinition::make()->addDataset('fragmented', 'COUNTER', 0);

            $fields = [
                'fragmented' => $oids[0]['pfCounterFragment'],
            ];

            $tags = ['rrd_def' => $rrd_def];
            $datastore->put($this->getDeviceArray(), 'pf_fragmented', $tags, $fields);

            $this->enableGraph('pf_fragmented');
        }

        if (is_numeric($oids[0]['pfCounterShort'] ?? null)) {
            $rrd_def = RrdDefinition::make()->addDataset('short', 'COUNTER', 0);

            $fields = [
                'short' => $oids[0]['pfCounterShort'],
            ];

            $tags = ['rrd_def' => $rrd_def];
            $datastore->put($this->getDeviceArray(), 'pf_short', $tags, $fields);

            $this->enableGraph('pf_short');
        }

        if (is_numeric($oids[0]['pfCounterNormalize'] ?? null)) {
            $rrd_def = RrdDefinition::make()->addDataset('normalized', 'COUNTER', 0);

            $fields = [
                'normalized' => $oids[0]['pfCounterNormalize'],
            ];

            $tags = ['rrd_def' => $rrd_def];
            $datastore->put($this->getDeviceArray(), 'pf_normalized', $tags, $fields);

            $this->enableGraph('pf_normalized');
        }

        if (is_numeric($oids[0]['pfCounterMemDrop'] ?? null)) {
            $rrd_def = RrdDefinition::make()->addDataset('memdropped', 'COUNTER', 0);

            $fields = [
                'memdropped' => $oids[0]['pfCounterMemDrop'],
            ];

            $tags = ['rrd_def' => $rrd_def];
            $datastore->put($this->getDeviceArray(), 'pf_memdropped', $tags, $fields);

            $this->enableGraph('pf_memdropped');
        }
    }
}
